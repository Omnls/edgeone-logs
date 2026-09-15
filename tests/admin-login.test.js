/**
 * tests/admin-login.test.js
 *
 * POST /logs-admin-login 核心逻辑测试。重点验证：
 *   1. 成功登录签发 session token，且不消耗/重置失败计数。
 *   2. 失败登录返回 401，并计入一次失败尝试。
 *   3. 达到限流上限后直接 429，不再比较密钥。
 *   4. 缺少配置、非 POST、JSON 解析失败等边界情况。
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { handleAdminLoginRequest } from "../server/routes/admin-login.js";
import { ENV_ADMIN_KEY } from "../server/routes/admin.js";
import { verifySessionToken } from "../server/lib/session.js";
import { MAX_FAILED_LOGINS_PER_HOUR, loginAttemptsKey } from "../server/lib/login-rate-limit.js";

const ADMIN_KEY = "admin-key-at-least-24-chars-long";
const ENV = { [ENV_ADMIN_KEY]: ADMIN_KEY };
const FIXED_NOW = new Date(Date.UTC(2026, 8, 12, 23, 5, 0));

class FakeStore {
  constructor(initial = {}) {
    this.objects = new Map(Object.entries(initial));
    this.setCalls = [];
  }
  async get(key) {
    const v = this.objects.get(key);
    return v === undefined ? null : v;
  }
  async setJSON(key, value) {
    this.setCalls.push({ key, value });
    this.objects.set(key, value);
  }
}

test("非 POST 方法返回 405 并带 Allow", async () => {
  const res = await handleAdminLoginRequest({
    method: "GET",
    parsedBody: {},
    env: ENV,
    store: new FakeStore(),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 405);
  assert.equal(res.headers.allow, "POST");
});

test("JSON 解析失败返回 400，不抛出", async () => {
  const res = await handleAdminLoginRequest({
    bodyParseFailed: true,
    env: ENV,
    store: new FakeStore(),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, "invalid_json_body");
});

test("请求体不是对象时返回 400", async () => {
  for (const bad of [null, [], "x", 5, undefined]) {
    const res = await handleAdminLoginRequest({
      parsedBody: bad,
      env: ENV,
      store: new FakeStore(),
      now: FIXED_NOW,
    });
    assert.equal(res.status, 400, `parsedBody=${JSON.stringify(bad)} 应 400`);
    assert.equal(res.body.error, "invalid_json_body");
  }
});

test("adminKey 缺失或为空返回 400", async () => {
  for (const bad of [{}, { adminKey: "" }, { adminKey: 123 }]) {
    const res = await handleAdminLoginRequest({
      parsedBody: bad,
      env: ENV,
      store: new FakeStore(),
      now: FIXED_NOW,
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, "missing_admin_key");
  }
});

test("未配置 ADMIN_SHARED_KEY 时返回 503", async () => {
  const res = await handleAdminLoginRequest({
    parsedBody: { adminKey: ADMIN_KEY },
    env: {},
    store: new FakeStore(),
    now: FIXED_NOW,
  });
  assert.equal(res.status, 503);
  assert.equal(res.body.error, "admin_key_not_configured");
});

test("密钥正确时返回 200 并签发有效的 session token", async () => {
  const store = new FakeStore();
  const res = await handleAdminLoginRequest({
    parsedBody: { adminKey: ADMIN_KEY },
    env: ENV,
    store,
    now: FIXED_NOW,
  });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
  assert.equal(typeof res.sessionToken, "string");
  assert.equal(
    verifySessionToken({ token: res.sessionToken, secret: ADMIN_KEY, now: FIXED_NOW }),
    true
  );
  // 成功登录不应该触碰失败计数器。
  assert.equal(store.setCalls.length, 0);
});

test("密钥错误时返回 401，并计入一次失败尝试", async () => {
  const store = new FakeStore();
  const res = await handleAdminLoginRequest({
    parsedBody: { adminKey: "wrong-key" },
    env: ENV,
    store,
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "invalid_admin_key");
  assert.equal(res.sessionToken, undefined);
  const key = loginAttemptsKey(FIXED_NOW);
  assert.equal(store.objects.get(key).failedCount, 1);
});

test("达到限流上限后返回 429，不再比较密钥（即使密钥正确也不放行）", async () => {
  const key = loginAttemptsKey(FIXED_NOW);
  const store = new FakeStore({ [key]: { failedCount: MAX_FAILED_LOGINS_PER_HOUR } });
  const res = await handleAdminLoginRequest({
    parsedBody: { adminKey: "wrong-key" },
    env: ENV,
    store,
    now: FIXED_NOW,
  });
  assert.equal(res.status, 429);
  assert.equal(res.body.error, "too_many_attempts");
  assert.equal(store.setCalls.length, 0);
});

test("限流存储不可用时优雅降级，失败登录仍返回 401 而不是 503", async () => {
  const res = await handleAdminLoginRequest({
    parsedBody: { adminKey: "wrong-key" },
    env: ENV,
    store: undefined,
    now: FIXED_NOW,
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "invalid_admin_key");
});
