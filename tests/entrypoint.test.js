/**
 * tests/entrypoint.test.js
 *
 * 走真实 Cloud Function 默认入口的集成测试。
 *
 * 与其他测试文件的区别：这里不调用 handleIngestRequest/handleAdminRequest，
 * 而是构造真实的 `Request`，调用 cloud-functions/ 下的默认导出，并检查真实的
 * `Response`。存储路径也走生产路径 getLogStore -> SDK getStore(name)，只把
 * SDK `Store` 原型上的三个方法（setJSON/get/list）替换成内存实现。
 *
 * 明确声明：这仍然是离线存储替身。被替换掉的是 SDK 与 COS 之间的实际传输，
 * 因此本文件不能证明真实 Pages 环境可写，也不能证明真实凭据交换可用；它证明
 * 的是「默认入口 + 生产 getStore 构造路径 + 业务逻辑 + 响应头」这一段是连通
 * 的，且入口不存在 context.store 之类的注入后门。真实投递写入需要 AC-13，
 * 本次未执行。
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";

import { Store } from "@edgeone/pages-blob";

import ingestEntry from "../cloud-functions/edgeone-logs.js";
import adminEntry from "../cloud-functions/logs-admin/index.js";
import loginEntry from "../cloud-functions/logs-admin-login/index.js";
import logoutEntry from "../cloud-functions/logs-admin-logout/index.js";

/** 官方连通性校验样例原文（docs/reference/61296.md:39-64），保留缩进与换行。 */
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
    "EdgeServerID": "336d5ebc5436534e61d16e63ddfca327",
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

const INGEST_KEY = "ingest-key-for-tests-0123456789";
const ADMIN_KEY = "admin-key-for-tests-0123456789";

/** 被替换掉的 SDK 原型方法，测试结束后还原。 */
const originalMethods = {
  setJSON: Store.prototype.setJSON,
  get: Store.prototype.get,
  list: Store.prototype.list,
};

/** 记录 SDK 实际收到的调用参数，用于断言一致性与条件写。 */
let blobs;
let calls;
let savedEnv;

beforeEach(() => {
  blobs = new Map();
  calls = { setJSON: [], get: [], list: [] };

  // 让 SDK 的 getStore(name) 能在离线环境构造成功：它只读这两个 process.env，
  // 凭据交换发生在实际网络调用时，而网络调用已被下面的原型替换拦下。
  savedEnv = {
    cred: process.env.PAGES_BLOB_DEPLOY_CREDENTIAL,
    project: process.env.PAGES_PROJECT_ID,
  };
  process.env.PAGES_BLOB_DEPLOY_CREDENTIAL = "offline-test-credential";
  process.env.PAGES_PROJECT_ID = "offline-test-project";

  Store.prototype.setJSON = async function (key, value, options) {
    calls.setJSON.push({ storeName: this.storeName, key, options });
    if (options?.onlyIfNew && blobs.has(key)) {
      const err = new Error("PagesBlob: conditional write failed");
      err.code = "PRECONDITION_FAILED";
      throw err;
    }
    // 与 SDK 行为一致：内部自行 JSON.stringify。
    blobs.set(key, JSON.stringify(value));
  };

  Store.prototype.get = async function (key, options) {
    calls.get.push({ key, options });
    const raw = blobs.get(key);
    if (raw === undefined) return null;
    return options?.type === "json" ? JSON.parse(raw) : raw;
  };

  Store.prototype.list = async function (options) {
    calls.list.push(options);
    const prefix = options?.prefix ?? "";
    const keys = Array.from(blobs.keys())
      .filter((k) => k.startsWith(prefix))
      .sort();
    const limit = options?.limit ?? keys.length;
    return {
      blobs: keys.slice(0, limit).map((k) => ({ key: k, etag: "etag-" + k })),
      directories: [],
    };
  };
});

afterEach(() => {
  Store.prototype.setJSON = originalMethods.setJSON;
  Store.prototype.get = originalMethods.get;
  Store.prototype.list = originalMethods.list;
  if (savedEnv.cred === undefined) delete process.env.PAGES_BLOB_DEPLOY_CREDENTIAL;
  else process.env.PAGES_BLOB_DEPLOY_CREDENTIAL = savedEnv.cred;
  if (savedEnv.project === undefined) delete process.env.PAGES_PROJECT_ID;
  else process.env.PAGES_PROJECT_ID = savedEnv.project;
});

function ingestEnv(extra = {}) {
  return { INGEST_SHARED_KEY: INGEST_KEY, BLOB_STORE: "logs-test-store", ...extra };
}

function adminEnv(extra = {}) {
  return { ADMIN_SHARED_KEY: ADMIN_KEY, BLOB_STORE: "logs-test-store", ...extra };
}

function postRequest(body, headers = {}) {
  return new Request("https://logs.example.com/edgeone-logs", {
    method: "POST",
    headers: { "x-ingest-key": INGEST_KEY, ...headers },
    body,
  });
}

function assertSecurityHeaders(response) {
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.match(response.headers.get("content-type"), /application\/json/);
}

test("默认入口接收官方原文样例并写入真实 getStore 取得的 Store", async () => {
  const response = await ingestEntry({
    request: postRequest(OFFICIAL_VERIFICATION_BODY),
    env: ingestEnv(),
  });

  assert.equal(response.status, 200);
  assertSecurityHeaders(response);

  const body = await response.json();
  assert.equal(body.result_code, 0);
  assert.equal(body.kind, "single-object");
  assert.equal(body.recordCount, 1);
  assert.equal(body.batchesWritten, 1);

  // store 名来自 BLOB_STORE，而不是任何请求侧输入。
  assert.equal(calls.setJSON.length, 1);
  assert.equal(calls.setJSON[0].storeName, "logs-test-store");
  // 条件写始终开启，保证重投幂等。
  assert.equal(calls.setJSON[0].options.onlyIfNew, true);
  // 分区键来自记录自身的 ISO8601 时间（2022-07-01T02:37:13Z）。
  assert.match(calls.setJSON[0].key, /^logs\/2022-07-01\/02\//);
});

test("入口不接受 context.store 注入后门", async () => {
  const fakeStore = {
    setJSON: async () => {
      throw new Error("注入的 store 不应被使用");
    },
  };
  const response = await ingestEntry({
    request: postRequest(OFFICIAL_VERIFICATION_BODY),
    env: ingestEnv(),
    store: fakeStore,
  });
  assert.equal(response.status, 200);
  // 写入仍然发生在 SDK Store 上，注入对象被忽略。
  assert.equal(calls.setJSON.length, 1);
});

test("gzip 投递经入口解压后写入", async () => {
  const ndjson = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z","EdgeResponseStatusCode":522}',
    '{"RequestID":"b","RequestTime":"2024-10-13T23:30:40Z","EdgeResponseStatusCode":200}',
  ].join("\n");
  const response = await ingestEntry({
    request: postRequest(gzipSync(Buffer.from(ndjson, "utf8")), {
      "content-encoding": "gzip",
    }),
    env: ingestEnv(),
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.kind, "ndjson");
  assert.equal(body.recordCount, 2);
  assert.equal(blobs.size, 1);
});

test("同一批次重投在入口层面幂等，不产生第二个对象", async () => {
  const first = await ingestEntry({
    request: postRequest(OFFICIAL_VERIFICATION_BODY),
    env: ingestEnv(),
  });
  const second = await ingestEntry({
    request: postRequest(OFFICIAL_VERIFICATION_BODY),
    env: ingestEnv(),
  });

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const secondBody = await second.json();
  assert.equal(secondBody.batchesDuplicate, 1);
  assert.equal(secondBody.batchesWritten, 0);
  assert.equal(blobs.size, 1);
});

test("跨 UTC 小时的一次投递落到各自小时分区", async () => {
  const ndjson = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:59:59Z"}',
    '{"RequestID":"b","RequestTime":"2024-10-14T00:00:01Z"}',
  ].join("\n");
  const response = await ingestEntry({
    request: postRequest(Buffer.from(ndjson, "utf8")),
    env: ingestEnv(),
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.partitions, 2);
  const keys = Array.from(blobs.keys()).sort();
  assert.equal(keys.length, 2);
  assert.match(keys[0], /^logs\/2024-10-13\/23\//);
  assert.match(keys[1], /^logs\/2024-10-14\/00\//);
});

test("ingest 入口拒绝非 POST 并带 Allow，且不读取正文", async () => {
  const response = await ingestEntry({
    request: new Request("https://logs.example.com/edgeone-logs", {
      method: "GET",
      headers: { "x-ingest-key": INGEST_KEY },
    }),
    env: ingestEnv(),
  });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
  assertSecurityHeaders(response);
  assert.equal(calls.setJSON.length, 0);
});

test("缺少 ingest key 时入口返回 401 且零写入", async () => {
  const response = await ingestEntry({
    request: new Request("https://logs.example.com/edgeone-logs", {
      method: "POST",
      body: OFFICIAL_VERIFICATION_BODY,
    }),
    env: ingestEnv(),
  });
  assert.equal(response.status, 401);
  assertSecurityHeaders(response);
  assert.equal(blobs.size, 0);
});

test("坏行导致整批 400 且零写入", async () => {
  const body = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}',
    "{ 坏行",
  ].join("\n");
  const response = await ingestEntry({
    request: postRequest(Buffer.from(body, "utf8")),
    env: ingestEnv(),
  });
  assert.equal(response.status, 400);
  assert.equal(blobs.size, 0);
  const payload = await response.json();
  assert.equal(payload.error, "invalid_record");
  // 不回显行内容。
  assert.ok(!JSON.stringify(payload).includes("坏行"));
});

test("BLOB_STORE 名非法时入口返回 503，不落入 SDK", async () => {
  const response = await ingestEntry({
    request: postRequest(OFFICIAL_VERIFICATION_BODY),
    env: ingestEnv({ BLOB_STORE: "bad/store:name" }),
  });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "storage_not_configured");
  assert.equal(calls.setJSON.length, 0);
});

test("管理入口经真实 Store 读回记录，且查询串已脱敏", async () => {
  const record = {
    RequestID: "req-1",
    RequestTime: "2024-10-13T23:30:39Z",
    RequestHost: "www.example.com",
    EdgeResponseStatusCode: 522,
    OriginResponseStatusCode: -1,
    EdgeException: "edge_response_exception.timeout",
    RequestUrlQueryString: "token=SHOULD_NOT_PERSIST&page=2",
    RequestReferer: "https://a.example.com/x?token=ALSO_SECRET",
  };
  const ingestResponse = await ingestEntry({
    request: postRequest(Buffer.from(JSON.stringify(record), "utf8")),
    env: ingestEnv(),
  });
  assert.equal(ingestResponse.status, 200);

  // 实际写入的字节里不允许出现凭据取值。
  const stored = Array.from(blobs.values()).join("");
  assert.ok(!stored.includes("SHOULD_NOT_PERSIST"));
  assert.ok(!stored.includes("ALSO_SECRET"));
  // 诊断字段必须保留。
  assert.ok(stored.includes("edge_response_exception.timeout"));

  const adminResponse = await adminEntry({
    request: new Request(
      "https://logs.example.com/logs-admin?date=2024-10-13&hour=23&status=522",
      { method: "GET", headers: { "x-admin-key": ADMIN_KEY } }
    ),
    env: adminEnv(),
  });

  assert.equal(adminResponse.status, 200);
  assertSecurityHeaders(adminResponse);
  const body = await adminResponse.json();
  assert.equal(body.matchedRecords, 1);
  assert.equal(body.scannedPartitions, 1);
  assert.equal(body.boundedPage, true);
  assert.equal(body.batches[0].records[0].RequestID, "req-1");
  assert.equal(body.batches[0].records[0].EdgeException, "edge_response_exception.timeout");

  // 列举与读取都必须使用 strong 一致性、禁用目录聚合与自动翻页。
  assert.equal(calls.list[0].consistency, "strong");
  assert.equal(calls.list[0].directories, false);
  assert.equal(calls.list[0].paginate, false);
  assert.equal(calls.get[0].options.consistency, "strong");
});

test("管理入口的非法参数由业务层拒绝，不被入口悄悄放宽", async () => {
  const response = await adminEntry({
    request: new Request(
      "https://logs.example.com/logs-admin?date=2024-10-13&hour=23&status=abc",
      { method: "GET", headers: { "x-admin-key": ADMIN_KEY } }
    ),
    env: adminEnv(),
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "invalid_status");
  assert.equal(calls.list.length, 0);
});

test("两种密钥不可互换", async () => {
  const ingestWithAdminKey = await ingestEntry({
    request: new Request("https://logs.example.com/edgeone-logs", {
      method: "POST",
      headers: { "x-ingest-key": ADMIN_KEY },
      body: OFFICIAL_VERIFICATION_BODY,
    }),
    env: ingestEnv({ ADMIN_SHARED_KEY: ADMIN_KEY }),
  });
  assert.equal(ingestWithAdminKey.status, 401);

  const adminWithIngestKey = await adminEntry({
    request: new Request("https://logs.example.com/logs-admin", {
      method: "GET",
      headers: { "x-admin-key": INGEST_KEY },
    }),
    env: adminEnv({ INGEST_SHARED_KEY: INGEST_KEY }),
  });
  assert.equal(adminWithIngestKey.status, 401);
});

test("管理入口拒绝非 GET", async () => {
  const response = await adminEntry({
    request: new Request("https://logs.example.com/logs-admin", {
      method: "DELETE",
      headers: { "x-admin-key": ADMIN_KEY },
    }),
    env: adminEnv(),
  });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET");
});

function loginRequest(bodyObj, headers = {}) {
  return new Request("https://logs.example.com/logs-admin-login", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(bodyObj),
  });
}

test("登录入口：正确密钥返回 200 且下发带全部安全属性的 Set-Cookie", async () => {
  const response = await loginEntry({
    request: loginRequest({ adminKey: ADMIN_KEY }),
    env: adminEnv(),
  });
  assert.equal(response.status, 200);
  assertSecurityHeaders(response);
  const body = await response.json();
  assert.equal(body.ok, true);

  const setCookie = response.headers.get("set-cookie");
  assert.ok(setCookie, "success response must set a cookie");
  assert.match(setCookie, /^eo_admin_session=/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Path=\//);
  assert.match(setCookie, /Max-Age=43200/);

  // 下发的 token 可以直接被管理查询接口通过 cookie 接受。
  const cookieValue = setCookie.split(";")[0];
  const adminResponse = await adminEntry({
    request: new Request("https://logs.example.com/logs-admin", {
      method: "GET",
      headers: { cookie: cookieValue },
    }),
    env: adminEnv(),
  });
  assert.equal(adminResponse.status, 200);
});

test("登录入口：错误密钥返回 401 且不带 Set-Cookie", async () => {
  const response = await loginEntry({
    request: loginRequest({ adminKey: "wrong-key" }),
    env: adminEnv(),
  });
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("set-cookie"), null);
});

test("登录入口：非 POST 返回 405 且带 Allow", async () => {
  const response = await loginEntry({
    request: new Request("https://logs.example.com/logs-admin-login", {
      method: "GET",
    }),
    env: adminEnv(),
  });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
});

test("登录入口：畸形 JSON 正文返回 400 而不是抛出异常", async () => {
  const response = await loginEntry({
    request: new Request("https://logs.example.com/logs-admin-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{ 这不是合法 JSON",
    }),
    env: adminEnv(),
  });
  assert.equal(response.status, 400);
  assertSecurityHeaders(response);
});

test("登录入口：未配置 ADMIN_SHARED_KEY 返回 503", async () => {
  const response = await loginEntry({
    request: loginRequest({ adminKey: ADMIN_KEY }),
    env: { BLOB_STORE: "logs-test-store" },
  });
  assert.equal(response.status, 503);
});

test("退出登录入口：POST 返回 200 且用已过期 Set-Cookie 清除会话", async () => {
  const response = await logoutEntry({
    request: new Request("https://logs.example.com/logs-admin-logout", {
      method: "POST",
    }),
    env: adminEnv(),
  });
  assert.equal(response.status, 200);
  const setCookie = response.headers.get("set-cookie");
  assert.match(setCookie, /^eo_admin_session=;/);
  assert.match(setCookie, /Max-Age=0/);
});

test("退出登录入口：非 POST 返回 405", async () => {
  const response = await logoutEntry({
    request: new Request("https://logs.example.com/logs-admin-logout", {
      method: "GET",
    }),
    env: adminEnv(),
  });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
});
