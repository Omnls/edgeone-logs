/**
 * tests/admin.test.js
 *
 * 管理查询测试。重点验证三件事：
 *   1. 存储读写失败绝不伪装成「零匹配」——空结果会被误读为「该小时没有日志」。
 *   2. 扫描范围严格限定在单个 UTC 小时前缀，且列举始终以有界方式调用。
 *   3. 两套密钥不可互换，缺配置即失败关闭。
 *
 * FakeStore 本身对调用参数做断言：任何一次列举缺少 directories:false /
 * paginate:false / consistency:'strong' 都会让测试失败，而不是悄悄放过。
 * 明确说明：这是离线存储替身，不代表真实 Pages Blob 可写。
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ADMIN_KEY_HEADER,
  DEFAULT_BATCH_LIMIT,
  ENV_ADMIN_KEY,
  MAX_BATCH_LIMIT,
  MAX_RESPONSE_BYTES,
  defaultUtcDateHour,
  handleAdminRequest,
  isValidCalendarDate,
  parseBoundedInt,
  recordMatchesFilters,
} from "../server/routes/admin.js";
import { createSessionToken } from "../server/lib/session.js";

const ADMIN_KEY = "admin-key-at-least-24-chars-long";
const INGEST_KEY = "ingest-key-at-least-24-chars-long";
const ENV = { [ENV_ADMIN_KEY]: ADMIN_KEY, INGEST_SHARED_KEY: INGEST_KEY };

/** 固定的「当前时间」，用于默认窗口断言：UTC 2026-09-12 23:05。 */
const FIXED_NOW = new Date(Date.UTC(2026, 8, 12, 23, 5, 0));

function record(overrides = {}) {
  return {
    RequestID: "r1",
    RequestHost: "logs.example.com",
    RequestTime: "2026-09-12T23:30:39Z",
    EdgeResponseStatusCode: 200,
    ...overrides,
  };
}

function batchPayload(batchId, records) {
  return {
    schemaVersion: 1,
    batchId,
    partitionTimestampMs: Date.UTC(2026, 8, 12, 23, 30, 39),
    recordCount: records.length,
    records,
  };
}

/**
 * 离线存储替身。对列举与读取的调用参数做强断言。
 */
class FakeStore {
  constructor(options = {}) {
    this.objects = options.objects ?? new Map();
    this.failList = options.failList ?? false;
    this.failGetKeys = options.failGetKeys ?? new Set();
    this.nullKeys = options.nullKeys ?? new Set();
    this.listCalls = [];
    this.getCalls = [];
  }

  async list(options) {
    this.listCalls.push(options);
    // 有界列举契约：这三项缺一即为缺陷，不允许静默通过。
    assert.equal(options.directories, false, "list 必须传 directories:false");
    assert.equal(options.paginate, false, "list 必须传 paginate:false");
    assert.equal(options.consistency, "strong", "list 必须使用 strong 一致性");
    assert.equal(typeof options.limit, "number", "list 必须带有限 limit");
    assert.ok(options.limit > 0 && options.limit <= MAX_BATCH_LIMIT);

    if (this.failList) throw new Error("list failed");

    const prefix = options.prefix ?? "";
    const all = Array.from(this.objects.keys())
      .filter((k) => k.startsWith(prefix))
      .sort();
    const start = options.cursor ? all.indexOf(options.cursor) : 0;
    const from = start < 0 ? 0 : start;
    const page = all.slice(from, from + options.limit);
    const next = all[from + options.limit];
    return {
      blobs: page.map((k) => ({ key: k, etag: `etag-${k}` })),
      directories: [],
      ...(next !== undefined ? { cursor: next } : {}),
    };
  }

  async get(key, options) {
    this.getCalls.push({ key, options });
    assert.equal(options.type, "json", "读取必须指定 type:json");
    assert.equal(options.consistency, "strong", "读取必须使用 strong 一致性");
    if (this.failGetKeys.has(key)) throw new Error("read failed");
    if (this.nullKeys.has(key)) return null;
    const v = this.objects.get(key);
    return v === undefined ? null : v;
  }
}

function storeWith(entries) {
  return new FakeStore({ objects: new Map(entries) });
}

async function query(extra = {}, store = storeWith([])) {
  return handleAdminRequest({
    adminKeyHeader: ADMIN_KEY,
    env: ENV,
    store,
    now: FIXED_NOW,
    ...extra,
  });
}

// ─── 鉴权与方法 ──────────────────────────────────────────────────────

test("未配置 ADMIN_SHARED_KEY 时失败关闭，返回 503 而不是放行", async () => {
  const res = await handleAdminRequest({
    adminKeyHeader: ADMIN_KEY,
    env: {},
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 503);
  assert.equal(res.body.error, "admin_key_not_configured");
});

test("ingest 密钥不能当作 admin 密钥使用（双权限隔离）", async () => {
  const res = await handleAdminRequest({
    adminKeyHeader: INGEST_KEY,
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "unauthorized");
});

test("缺少密钥请求头返回 401", async () => {
  const res = await handleAdminRequest({
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
});

test("非 GET 方法返回 405 并带 Allow", async () => {
  const res = await query({ method: "POST" });
  assert.equal(res.status, 405);
  assert.equal(res.headers.allow, "GET");
});

test("鉴权先于任何存储 I/O：401 时不触碰 store", async () => {
  const store = storeWith([
    ["logs/2026-09-12/23/a.json", batchPayload("a", [record()])],
  ]);
  const res = await handleAdminRequest({
    adminKeyHeader: "wrong",
    env: ENV,
    store,
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
  assert.equal(store.listCalls.length, 0);
  assert.equal(store.getCalls.length, 0);
});

// ─── session cookie 鉴权（登录后免带 X-Admin-Key） ──────────────────

test("有效 session cookie 可以替代 X-Admin-Key 通过鉴权", async () => {
  const token = createSessionToken({ secret: ADMIN_KEY, now: FIXED_NOW });
  const res = await handleAdminRequest({
    sessionCookie: token,
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 200);
});

test("过期的 session cookie 被拒绝，返回 401", async () => {
  const issuedAt = new Date(FIXED_NOW.getTime() - 13 * 60 * 60 * 1000); // 13 小时前签发
  const token = createSessionToken({ secret: ADMIN_KEY, now: issuedAt });
  const res = await handleAdminRequest({
    sessionCookie: token,
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "unauthorized");
});

test("被篡改的 session cookie 被拒绝，返回 401", async () => {
  const token = createSessionToken({ secret: ADMIN_KEY, now: FIXED_NOW });
  const [payloadB64, hmacB64] = token.split(".");
  const tamperedHmac = hmacB64.slice(0, -1) + (hmacB64.at(-1) === "A" ? "B" : "A");
  const tampered = `${payloadB64}.${tamperedHmac}`;
  const res = await handleAdminRequest({
    sessionCookie: tampered,
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "unauthorized");
});

test("X-Admin-Key 与 session cookie 都缺失或都无效时才 401", async () => {
  const res = await handleAdminRequest({
    adminKeyHeader: "wrong",
    sessionCookie: "not-a-valid-token",
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
});

test("X-Admin-Key 正确时即使 cookie 无效也放行（两条路径任一通过即可）", async () => {
  const res = await handleAdminRequest({
    adminKeyHeader: ADMIN_KEY,
    sessionCookie: "garbage",
    env: ENV,
    store: storeWith([]),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 200);
});

// ─── 参数校验 ────────────────────────────────────────────────────────

test("date 与 hour 必须成对出现", async () => {
  const only = await query({ date: "2026-09-12" });
  assert.equal(only.status, 400);
  assert.equal(only.body.error, "date_and_hour_must_be_given_together");

  const onlyHour = await query({ hour: "23" });
  assert.equal(onlyHour.status, 400);
});

test("非法日历日期被拒绝，不静默改写", async () => {
  for (const bad of ["2026-02-30", "2026-13-01", "2026-9-1", "not-a-date"]) {
    const res = await query({ date: bad, hour: "23" });
    assert.equal(res.status, 400, `${bad} 应被拒绝`);
    assert.equal(res.body.error, "invalid_date");
  }
  assert.equal(isValidCalendarDate("2024-02-29"), true);
  assert.equal(isValidCalendarDate("2026-02-29"), false);
});

test("小时必须是 00..23", async () => {
  for (const bad of ["24", "99", "7", "aa"]) {
    const res = await query({ date: "2026-09-12", hour: bad });
    assert.equal(res.status, 400, `${bad} 应被拒绝`);
    assert.equal(res.body.error, "invalid_hour");
  }
});

test("非法 limit 返回 400，不静默改成默认值", async () => {
  for (const bad of ["0", "11", "-1", "abc", "1.5"]) {
    const res = await query({ limit: bad });
    assert.equal(res.status, 400, `limit=${bad} 应被拒绝`);
    assert.equal(res.body.error, "invalid_limit");
  }
});

test("未给 limit 时使用有界默认值，并在响应中回报", async () => {
  const res = await query();
  assert.equal(res.status, 200);
  assert.equal(res.body.batchLimit, DEFAULT_BATCH_LIMIT);
  assert.ok(DEFAULT_BATCH_LIMIT <= MAX_BATCH_LIMIT);
});

test("非法状态码参数被拒绝", async () => {
  const bad = await query({ status: "99" });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, "invalid_status");

  const badRange = await query({ statusMin: "600" });
  assert.equal(badRange.status, 400);
  assert.equal(badRange.body.error, "invalid_status_min");
});

test("状态区间倒置与单值/区间混用被拒绝", async () => {
  const inverted = await query({ statusMin: "500", statusMax: "400" });
  assert.equal(inverted.status, 400);
  assert.equal(inverted.body.error, "status_range_inverted");

  const mixed = await query({ status: "522", statusMin: "500" });
  assert.equal(mixed.status, 400);
  assert.equal(mixed.body.error, "status_and_range_are_mutually_exclusive");
});

test("parseBoundedInt 只接受范围内的整数", () => {
  assert.equal(parseBoundedInt(undefined, { min: 1, max: 10 }), undefined);
  // 显式空值（?limit=）按非法处理：静默忽略会让调用方以为筛选生效了。
  assert.equal(parseBoundedInt("", { min: 1, max: 10 }), "invalid");
  assert.equal(parseBoundedInt("5", { min: 1, max: 10 }), 5);
  assert.equal(parseBoundedInt("0", { min: 1, max: 10 }), "invalid");
  assert.equal(parseBoundedInt("1e3", { min: 1, max: 10 }), "invalid");
});

// ─── 存储失败必须显式报错 ────────────────────────────────────────────

test("列举失败返回 500，绝不伪装成零匹配", async () => {
  const store = new FakeStore({ failList: true });
  const res = await query({}, store);
  assert.equal(res.status, 500);
  assert.equal(res.body.error, "storage_list_failed");
  assert.ok(!("matchedRecords" in res.body));
});

test("单个批次读取失败返回 500，不跳过该批次", async () => {
  const key = "logs/2026-09-12/23/a.json";
  const store = new FakeStore({
    objects: new Map([[key, batchPayload("a", [record()])]]),
    failGetKeys: new Set([key]),
  });
  const res = await query({}, store);
  assert.equal(res.status, 500);
  assert.equal(res.body.error, "storage_read_failed");
});

test("列举有键但读回 null：状态不一致，显式报错", async () => {
  const key = "logs/2026-09-12/23/a.json";
  const store = new FakeStore({
    objects: new Map([[key, batchPayload("a", [record()])]]),
    nullKeys: new Set([key]),
  });
  const res = await query({}, store);
  assert.equal(res.status, 500);
  assert.equal(res.body.error, "batch_missing_after_list");
});

test("批次 schema 损坏显式失败，不当作零匹配", async () => {
  const store = storeWith([
    ["logs/2026-09-12/23/a.json", { batchId: "a", records: "not-an-array" }],
  ]);
  const res = await query({}, store);
  assert.equal(res.status, 500);
  assert.equal(res.body.error, "batch_schema_invalid");
});

// ─── 查询语义 ────────────────────────────────────────────────────────

test("默认窗口取当前 UTC 小时，并明确标注", async () => {
  const res = await query();
  assert.equal(res.status, 200);
  assert.equal(res.body.usedDefaultWindow, true);
  const expected = defaultUtcDateHour(FIXED_NOW);
  assert.equal(res.body.datePart, expected.datePart);
  assert.equal(res.body.hourPart, expected.hourPart);
  assert.equal(res.body.datePart, "2026-09-12");
  assert.equal(res.body.hourPart, "23");
});

test("扫描范围严格限定单个小时前缀", async () => {
  const store = storeWith([
    ["logs/2026-09-12/22/a.json", batchPayload("a", [record()])],
    ["logs/2026-09-12/23/b.json", batchPayload("b", [record()])],
    ["logs/2026-09-13/00/c.json", batchPayload("c", [record()])],
  ]);
  const res = await query({ date: "2026-09-12", hour: "23" }, store);
  assert.equal(res.status, 200);
  assert.equal(store.listCalls[0].prefix, "logs/2026-09-12/23/");
  assert.equal(res.body.scannedPartitions, 1);
  assert.equal(res.body.scannedBatches, 1);
  assert.equal(res.body.matchedRecords, 1);
  assert.equal(res.body.batches[0].key, "logs/2026-09-12/23/b.json");
});

test("522 排查：命中 OriginResponseStatusCode 而不只看边缘状态码", async () => {
  const store = storeWith([
    [
      "logs/2026-09-12/23/a.json",
      batchPayload("a", [
        record({ RequestID: "ok", EdgeResponseStatusCode: 200 }),
        record({
          RequestID: "bad",
          EdgeResponseStatusCode: 522,
          OriginResponseStatusCode: 0,
          EdgeException: "ORIGIN_CONNECT_TIMEOUT",
        }),
        record({
          RequestID: "origin5xx",
          EdgeResponseStatusCode: 200,
          OriginResponseStatusCode: 503,
        }),
      ]),
    ],
  ]);

  const only522 = await query({ status: "522" }, store);
  assert.equal(only522.body.matchedRecords, 1);
  assert.equal(only522.body.batches[0].records[0].RequestID, "bad");
  // 回源诊断字段必须保留，未来新增取值不能被枚举丢弃。
  assert.equal(
    only522.body.batches[0].records[0].EdgeException,
    "ORIGIN_CONNECT_TIMEOUT"
  );

  const range5xx = await query({ statusMin: "500", statusMax: "599" }, store);
  assert.equal(range5xx.body.matchedRecords, 2);
});

test("Host 与 RequestID 过滤生效", async () => {
  const store = storeWith([
    [
      "logs/2026-09-12/23/a.json",
      batchPayload("a", [
        record({ RequestID: "r1", RequestHost: "a.example.com" }),
        record({ RequestID: "r2", RequestHost: "b.example.com" }),
      ]),
    ],
  ]);
  const byHost = await query({ requestHost: "b.example.com" }, store);
  assert.equal(byHost.body.matchedRecords, 1);
  const byId = await query({ requestId: "r1" }, store);
  assert.equal(byId.body.matchedRecords, 1);
  const none = await query({ requestId: "nope" }, store);
  assert.equal(none.status, 200);
  assert.equal(none.body.matchedRecords, 0);
});

test("recordMatchesFilters 对缺失状态码不做宽松放行", () => {
  assert.equal(
    recordMatchesFilters({ RequestID: "x" }, { statusCode: 522 }),
    false
  );
  assert.equal(
    recordMatchesFilters({ OriginResponseStatusCode: "503" }, { statusMin: 500, statusMax: 599 }),
    true
  );
});

test("响应字节预算超出时返回 413，不静默截断", async () => {
  const big = record({ RequestUA: "U".repeat(4096) });
  const store = storeWith([
    ["logs/2026-09-12/23/a.json", batchPayload("a", [big])],
  ]);
  const res = await query({ maxResponseBytes: 512 }, store);
  assert.equal(res.status, 413);
  assert.equal(res.body.error, "response_budget_exceeded");
});

test("分页游标透传并回报，且明确这是有界页", async () => {
  const entries = [];
  for (let i = 0; i < 8; i += 1) {
    entries.push([
      `logs/2026-09-12/23/b${i}.json`,
      batchPayload(`b${i}`, [record({ RequestID: `r${i}` })]),
    ]);
  }
  const store = storeWith(entries);
  const first = await query({ limit: "3" }, store);
  assert.equal(first.status, 200);
  assert.equal(first.body.boundedPage, true);
  assert.equal(first.body.scannedBatches, 3);
  assert.equal(typeof first.body.cursor, "string");

  const second = await query({ limit: "3", cursor: first.body.cursor }, store);
  assert.equal(second.status, 200);
  assert.equal(second.body.scannedBatches, 3);
  assert.notEqual(second.body.batches[0].key, first.body.batches[0].key);
});

test("响应统计只描述当前页，且默认预算为自设上限", async () => {
  const res = await query();
  assert.match(res.body.note, /bounded page/);
  assert.equal(MAX_RESPONSE_BYTES, 5 * 1024 * 1024);
});

test("管理端密钥请求头名固定为 x-admin-key", () => {
  assert.equal(ADMIN_KEY_HEADER, "x-admin-key");
});
