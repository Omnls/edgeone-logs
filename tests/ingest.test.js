/**
 * tests/ingest.test.js
 *
 * 接收端测试。使用离线的 FakeStore 替身：这里验证的是本项目的业务逻辑，
 * 不是真实 Pages Blob 可写性。真实平台写入未验证，见 docs/operations.md。
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";

import {
  ENV_EDGEONE_SECRET_ID,
  ENV_EDGEONE_SECRET_KEY,
  ENV_INGEST_KEY,
  chunkRecords,
  deriveBatchId,
  groupRecordsByUtcHour,
  handleIngestRequest,
  parseRecordTimestampMs,
  resolveSignatureConfig,
} from "../server/routes/ingest.js";

/** 官方连通性校验测试数据原文（docs/reference/61296.md:39-64）。 */
const OFFICIAL_VERIFICATION_BODY = `{
    "ClientState": "CH-AH",
    "EdgeResponseTime": 366,
    "RequestID": "13515444256055847385",
    "ClientRegion": "CN",
    "RemotePort": 443,
    "RequestHost": "www.tencent.com",
    "RequestMethod": "GET",
    "RequestUrlQueryString": "-",
    "RequestUrl": "/en-us/about.html",
    "RequestProtocol": "HTTP/2.0",
    "EdgeServerID": "336d5ebc5436534e61d16e63ddfca327-d41d8cd98f00b204e9800998ecf8427e",
    "RequestTime": "2022-07-01T02:37:13Z",
    "EdgeCacheStatus": "-",
    "EdgeResponseBytes": 39430,
    "EdgeResponseStatusCode": 200,
    "ClientIP": "0.0.0.0",
    "RequestReferer": "https://www.tencent.com/",
    "RequestUA": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X)",
    "EdgeServerIP": "0.0.0.0",
    "RequestRange": "0-100/200",
    "EdgeInternalTime": 334,
    "RequestBytes": 237
}`;

const INGEST_KEY = "test-ingest-key-at-least-24-chars";

/**
 * 离线存储替身。断言调用方始终传入有界列举参数。
 */
class FakeStore {
  constructor() {
    /** @type {Map<string, unknown>} */
    this.objects = new Map();
    this.setCalls = [];
    this.failNextSet = null;
  }

  async setJSON(key, value, options) {
    this.setCalls.push({ key, options });
    if (this.failNextSet !== null) {
      const err = this.failNextSet;
      this.failNextSet = null;
      throw err;
    }
    if (options?.onlyIfNew && this.objects.has(key)) {
      const err = new Error("PagesBlob: conditional write failed");
      err.code = "PRECONDITION_FAILED";
      throw err;
    }
    this.objects.set(key, JSON.parse(JSON.stringify(value)));
  }

  async get(key, options) {
    assert.equal(options?.consistency, "strong", "读取必须使用 strong 一致性");
    return this.objects.has(key) ? this.objects.get(key) : null;
  }
}

/**
 * @param {object} [overrides]
 */
function baseArgs(overrides = {}) {
  return {
    method: "POST",
    rawBody: Buffer.from("", "utf8"),
    contentEncoding: undefined,
    requestPath: "/edgeone-logs",
    queryParams: new URLSearchParams(),
    ingestKeyHeader: INGEST_KEY,
    env: { [ENV_INGEST_KEY]: INGEST_KEY },
    store: new FakeStore(),
    ...overrides,
  };
}

test("官方连通性校验原文被接受并按 ISO8601 时间落到正确分区", async () => {
  const store = new FakeStore();
  const res = await handleIngestRequest(
    baseArgs({
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
      store,
    })
  );
  assert.equal(res.status, 200);
  assert.equal(res.body.result_code, 0);
  assert.equal(res.body.kind, "single-object");
  assert.equal(res.body.recordCount, 1);
  assert.equal(res.body.batchesWritten, 1);
  // 2022-07-01T02:37:13Z -> UTC 2022-07-01 02 时分区。
  const keys = Array.from(store.objects.keys());
  assert.equal(keys.length, 1);
  assert.match(keys[0], /^logs\/2022-07-01\/02\//);
});

test("真实 ISO8601 NDJSON 跨小时投递拆成多个分区，不塞进同一小时", async () => {
  const store = new FakeStore();
  const body = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:59:58Z","EdgeResponseStatusCode":200}',
    '{"RequestID":"b","RequestTime":"2024-10-14T00:00:03Z","EdgeResponseStatusCode":522}',
  ].join("\n");
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(res.status, 200);
  assert.equal(res.body.partitions, 2);
  const keys = Array.from(store.objects.keys()).sort();
  assert.equal(keys.length, 2);
  assert.match(keys[0], /^logs\/2024-10-13\/23\//);
  assert.match(keys[1], /^logs\/2024-10-14\/00\//);
});

test("gzip 投递被正确解压并落盘", async () => {
  const store = new FakeStore();
  const body = '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}';
  const res = await handleIngestRequest(
    baseArgs({
      rawBody: gzipSync(Buffer.from(body, "utf8")),
      contentEncoding: "gzip",
      store,
    })
  );
  assert.equal(res.status, 200);
  assert.equal(res.body.recordCount, 1);
});

test("JSON 数组形态被接受", async () => {
  const store = new FakeStore();
  const body = JSON.stringify([
    { RequestID: "a", RequestTime: "2024-10-13T23:30:39Z" },
    { RequestID: "b", RequestTime: "2024-10-13T23:30:40Z" },
  ]);
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(res.status, 200);
  assert.equal(res.body.recordCount, 2);
});

test("522 与回源诊断字段被完整保留", async () => {
  const store = new FakeStore();
  const body = JSON.stringify({
    RequestID: "r1",
    RequestTime: "2024-10-13T23:30:39Z",
    EdgeResponseStatusCode: 522,
    OriginResponseStatusCode: 0,
    EdgeException: "ORIGIN_CONNECT_TIMEOUT",
    RequestHost: "example.com",
  });
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(res.status, 200);
  const stored = Array.from(store.objects.values())[0];
  const rec = stored.records[0];
  assert.equal(rec.EdgeResponseStatusCode, 522);
  assert.equal(rec.OriginResponseStatusCode, 0);
  assert.equal(rec.EdgeException, "ORIGIN_CONNECT_TIMEOUT");
  assert.equal(rec.RequestID, "r1");
});

test("坏行导致整批 400 且零写入", async () => {
  const store = new FakeStore();
  const body = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}',
    "{ broken",
  ].join("\n");
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "invalid_record");
  assert.equal(store.objects.size, 0, "整批拒绝时不允许有任何写入");
  assert.equal(store.setCalls.length, 0);
});

test("缺少可用时间字段整批 400，不用当前时间伪造分区", async () => {
  const store = new FakeStore();
  const body = JSON.stringify({ RequestID: "a", RequestTime: "-" });
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "missing_record_timestamp");
  assert.equal(store.objects.size, 0);
});

test("相同内容重投命中 duplicate，不重复存储", async () => {
  const store = new FakeStore();
  const body = '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}';
  const first = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  const second = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(first.body.batchesWritten, 1);
  assert.equal(second.status, 200);
  assert.equal(second.body.batchesDuplicate, 1);
  assert.equal(second.body.batchesWritten, 0);
  assert.equal(store.objects.size, 1);
});

test("相同 RequestID 但内容不同必须落到不同键，不被误判为重复", async () => {
  const store = new FakeStore();
  const a = '{"RequestID":"same","RequestTime":"2024-10-13T23:30:39Z","EdgeResponseBytes":1}';
  const b = '{"RequestID":"same","RequestTime":"2024-10-13T23:30:39Z","EdgeResponseBytes":2}';
  await handleIngestRequest(baseArgs({ rawBody: Buffer.from(a, "utf8"), store }));
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(b, "utf8"), store })
  );
  assert.equal(res.body.batchesWritten, 1);
  assert.equal(store.objects.size, 2, "内容不同必须产生两个批次");
});

test("存储失败返回 500，调用方需重投", async () => {
  const store = new FakeStore();
  store.failNextSet = Object.assign(new Error("PagesBlob: rate limited"), {
    code: "RATE_LIMITED",
  });
  const body = '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}';
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(body, "utf8"), store })
  );
  assert.equal(res.status, 500);
  assert.equal(res.body.error, "storage_error");
});

test("非 POST 返回 405 并带 Allow", async () => {
  const res = await handleIngestRequest(baseArgs({ method: "GET" }));
  assert.equal(res.status, 405);
  assert.equal(res.headers.allow, "POST");
});

test("缺少 INGEST_SHARED_KEY 配置时失败关闭返回 503", async () => {
  const res = await handleIngestRequest(
    baseArgs({
      env: {},
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 503);
  assert.equal(res.body.error, "ingest_key_not_configured");
});

test("ingest key 不匹配返回 401，且在解析之前拒绝", async () => {
  const store = new FakeStore();
  const res = await handleIngestRequest(
    baseArgs({
      ingestKeyHeader: "wrong-key",
      rawBody: Buffer.from("{ broken", "utf8"),
      store,
    })
  );
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "unauthorized");
  assert.equal(store.objects.size, 0);
});

test("鉴权先于体积检查：无密钥的超限请求返回 401，不泄漏体积上限", async () => {
  // 鉴权前置是有意设计：未通过鉴权的请求不应从错误码里得知服务端的体积配置。
  const res = await handleIngestRequest(
    baseArgs({
      rawBody: Buffer.alloc(2048, 0x41),
      maxBodyBytes: 1024,
      ingestKeyHeader: undefined,
    })
  );
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "unauthorized");
  assert.ok(!("maxBytes" in res.body));
});

test("通过鉴权后体积超限返回 413，且零写入", async () => {
  const store = new FakeStore();
  const res = await handleIngestRequest(
    baseArgs({
      rawBody: Buffer.alloc(2048, 0x41),
      maxBodyBytes: 1024,
      store,
    })
  );
  assert.equal(res.status, 413);
  assert.equal(res.body.error, "payload_too_large");
  assert.equal(store.objects.size, 0);
});

test("admin key 不能当作 ingest key 使用", async () => {
  const res = await handleIngestRequest(
    baseArgs({
      env: { [ENV_INGEST_KEY]: INGEST_KEY, ADMIN_SHARED_KEY: "admin-key-value" },
      ingestKeyHeader: "admin-key-value",
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 401);
});

// ─── 官方签名 ────────────────────────────────────────────────────────

const SECRET_ID = "TestSecretId";
const SECRET_KEY = "0123456789abcdef0123456789abcdef"; // 官方要求固定 32 位

function signedQuery({ uri, timestamp, rand }) {
  const md5 = createHash("md5")
    .update(`${uri}-${timestamp}-${rand}-${SECRET_KEY}`, "utf8")
    .digest("hex");
  return new URLSearchParams({
    auth_key: `${timestamp}-${rand}-${md5}`,
    access_key: SECRET_ID,
  });
}

const SIGNED_ENV = {
  [ENV_INGEST_KEY]: INGEST_KEY,
  [ENV_EDGEONE_SECRET_ID]: SECRET_ID,
  [ENV_EDGEONE_SECRET_KEY]: SECRET_KEY,
};

test("配置签名后，合法签名投递通过", async () => {
  const timestamp = 1571587200;
  const res = await handleIngestRequest(
    baseArgs({
      env: SIGNED_ENV,
      queryParams: signedQuery({ uri: "/edgeone-logs", timestamp, rand: 12345 }),
      nowSeconds: timestamp + 10,
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 200);
});

test("配置签名后，省略签名参数不能降级绕过", async () => {
  const res = await handleIngestRequest(
    baseArgs({
      env: SIGNED_ENV,
      queryParams: new URLSearchParams(),
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "unauthorized");
});

test("只带一个签名参数被拒绝", async () => {
  const res = await handleIngestRequest(
    baseArgs({
      env: SIGNED_ENV,
      queryParams: new URLSearchParams({ access_key: SECRET_ID }),
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 401);
});

test("重复签名参数被拒绝", async () => {
  const timestamp = 1571587200;
  const q = signedQuery({ uri: "/edgeone-logs", timestamp, rand: 1 });
  q.append("auth_key", "duplicate-value");
  const res = await handleIngestRequest(
    baseArgs({
      env: SIGNED_ENV,
      queryParams: q,
      nowSeconds: timestamp,
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 401);
});

test("过期与将来时间的签名都被拒绝", async () => {
  const timestamp = 1571587200;
  const q = signedQuery({ uri: "/edgeone-logs", timestamp, rand: 1 });
  for (const now of [timestamp + 3600, timestamp - 3600]) {
    const res = await handleIngestRequest(
      baseArgs({
        env: SIGNED_ENV,
        queryParams: q,
        nowSeconds: now,
        rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
      })
    );
    assert.equal(res.status, 401);
  }
});

test("半配置签名返回 503，不猜测意图", async () => {
  const res = await handleIngestRequest(
    baseArgs({
      env: { [ENV_INGEST_KEY]: INGEST_KEY, [ENV_EDGEONE_SECRET_ID]: SECRET_ID },
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 503);
  assert.equal(res.body.error, "signature_config_invalid");
});

test("SecretKey 长度不是官方要求的 32 位时视为配置错误", () => {
  const cfg = resolveSignatureConfig({
    [ENV_EDGEONE_SECRET_ID]: SECRET_ID,
    [ENV_EDGEONE_SECRET_KEY]: "short",
  });
  assert.equal(cfg.mode, "misconfigured");
});

test("未配置签名却带签名参数：拒绝而不是忽略", async () => {
  const timestamp = 1571587200;
  const res = await handleIngestRequest(
    baseArgs({
      queryParams: signedQuery({ uri: "/edgeone-logs", timestamp, rand: 1 }),
      nowSeconds: timestamp,
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
    })
  );
  assert.equal(res.status, 401);
});

test("未配置签名且不带签名参数：独立 header 鉴权正常可用", async () => {
  const res = await handleIngestRequest(
    baseArgs({ rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8") })
  );
  assert.equal(res.status, 200);
});

// ─── 纯函数 ──────────────────────────────────────────────────────────

test("parseRecordTimestampMs 只接受明确格式，不做模糊猜测", () => {
  assert.equal(parseRecordTimestampMs("2024-10-14T05:13:43Z"), 1728882823000);
  assert.equal(parseRecordTimestampMs("2024-10-14T05:13:43.500Z"), 1728882823500);
  assert.equal(parseRecordTimestampMs("2024-10-14T13:13:43+08:00"), 1728882823000);
  assert.equal(parseRecordTimestampMs("1728882823"), 1728882823000);
  assert.equal(parseRecordTimestampMs("1728882823000"), 1728882823000);
  assert.equal(parseRecordTimestampMs("-"), null);
  assert.equal(parseRecordTimestampMs(""), null);
  assert.equal(parseRecordTimestampMs("2024-10-14"), null);
  assert.equal(parseRecordTimestampMs("not a time"), null);
  assert.equal(parseRecordTimestampMs(undefined), null);
});

test("groupRecordsByUtcHour 取组内最早时间作为分区时间", () => {
  const { groups, missing } = groupRecordsByUtcHour([
    { RequestTime: "2024-10-13T23:59:59Z" },
    { RequestTime: "2024-10-13T23:00:01Z" },
    { RequestTime: "2024-10-14T00:00:01Z" },
    { RequestTime: "-" },
  ]);
  assert.equal(missing, 1);
  assert.equal(groups.length, 2);
  assert.equal(groups[0].partitionTimestampMs, Date.parse("2024-10-13T23:00:01Z"));
  assert.equal(groups[0].records.length, 2);
});

test("chunkRecords 切分稳定且不丢记录", () => {
  const records = Array.from({ length: 10 }, (_, i) => ({ i, pad: "x".repeat(50) }));
  const a = chunkRecords(records, 400, 5000);
  const b = chunkRecords(records, 400, 5000);
  assert.equal(a.oversizeIndex, null);
  assert.ok(a.chunks.length > 1);
  assert.deepEqual(a.chunks, b.chunks, "相同输入必须得到相同切分");
  assert.equal(a.chunks.flat().length, 10, "切分不得丢记录");
});

test("chunkRecords 对单条超限记录报 oversizeIndex，不截断", () => {
  const records = [{ ok: 1 }, { big: "x".repeat(500) }];
  const { oversizeIndex } = chunkRecords(records, 100, 5000);
  assert.equal(oversizeIndex, 1);
});

test("单条记录超过批次上限返回 413 且零写入", async () => {
  const store = new FakeStore();
  const body = JSON.stringify({
    RequestID: "big",
    RequestTime: "2024-10-13T23:30:39Z",
    Filler: "x".repeat(5000),
  });
  const res = await handleIngestRequest(
    baseArgs({
      rawBody: Buffer.from(body, "utf8"),
      store,
      maxBatchBytes: 2048,
    })
  );
  assert.equal(res.status, 413);
  assert.equal(res.body.error, "record_too_large");
  assert.equal(store.objects.size, 0);
});

test("deriveBatchId 由内容派生、完整 64 位摘要且为安全键片段", () => {
  const id = deriveBatchId([{ a: 1 }]);
  // 完整 SHA-256 十六进制，不做截断：截断会无谓抬高不同内容撞键的概率，
  // 而撞键在条件写语义下会被误判为重复投递。
  assert.match(id, /^[a-f0-9]{64}$/);
  assert.equal(deriveBatchId([{ a: 1 }]), id);
  assert.notEqual(deriveBatchId([{ a: 2 }]), id);
  // 键身份只取决于内容，不取决于对象键顺序或记录顺序。
  assert.equal(
    deriveBatchId([{ a: 1, b: 2 }]),
    deriveBatchId([{ b: 2, a: 1 }])
  );
  assert.equal(
    deriveBatchId([{ a: 1 }, { a: 2 }]),
    deriveBatchId([{ a: 2 }, { a: 1 }])
  );
});

test("写入始终使用 onlyIfNew 条件写", async () => {
  const store = new FakeStore();
  await handleIngestRequest(
    baseArgs({
      rawBody: Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"),
      store,
    })
  );
  assert.ok(store.setCalls.length > 0);
  for (const call of store.setCalls) {
    assert.equal(call.options?.onlyIfNew, true);
  }
});
