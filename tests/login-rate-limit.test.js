/**
 * tests/login-rate-limit.test.js
 *
 * 登录失败限流的单元测试。重点验证三件事：
 *   1. 未达上限时正常计数，不拒绝。
 *   2. 达到上限后直接判定限流，且不再写入（避免无界增长）。
 *   3. 存储不可用或读写失败时优雅降级，不阻塞登录判定本身。
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MAX_FAILED_LOGINS_PER_HOUR,
  loginAttemptsKey,
  recordFailedLoginAttempt,
} from "../server/lib/login-rate-limit.js";

/** 固定时间：UTC 2026-09-12 23:05:00。 */
const FIXED_NOW = new Date(Date.UTC(2026, 8, 12, 23, 5, 0));

class FakeStore {
  constructor(initial = {}) {
    this.objects = new Map(Object.entries(initial));
    this.setCalls = [];
    this.failGet = false;
    this.failSet = false;
  }

  async get(key) {
    if (this.failGet) throw new Error("read failed");
    const v = this.objects.get(key);
    return v === undefined ? null : v;
  }

  async setJSON(key, value) {
    this.setCalls.push({ key, value });
    if (this.failSet) throw new Error("write failed");
    this.objects.set(key, value);
  }
}

test("loginAttemptsKey 按 UTC 日期与小时分桶", () => {
  assert.equal(
    loginAttemptsKey(FIXED_NOW),
    "security/login-attempts/2026-09-12/23.json"
  );
});

test("未达上限时正常计数，返回 false（不限流）", async () => {
  const store = new FakeStore();
  const limited = await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  assert.equal(limited, false);
  const key = loginAttemptsKey(FIXED_NOW);
  assert.equal(store.objects.get(key).failedCount, 1);
});

test("连续失败会累加计数", async () => {
  const store = new FakeStore();
  for (let i = 0; i < 5; i += 1) {
    await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  }
  const key = loginAttemptsKey(FIXED_NOW);
  assert.equal(store.objects.get(key).failedCount, 5);
});

test("达到上限后返回 true（429），且不再写入", async () => {
  const key = loginAttemptsKey(FIXED_NOW);
  const store = new FakeStore({
    [key]: { failedCount: MAX_FAILED_LOGINS_PER_HOUR },
  });
  const limited = await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  assert.equal(limited, true);
  assert.equal(store.setCalls.length, 0);
  assert.equal(store.objects.get(key).failedCount, MAX_FAILED_LOGINS_PER_HOUR);
});

test("超过上限同样判定限流", async () => {
  const key = loginAttemptsKey(FIXED_NOW);
  const store = new FakeStore({
    [key]: { failedCount: MAX_FAILED_LOGINS_PER_HOUR + 3 },
  });
  const limited = await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  assert.equal(limited, true);
  assert.equal(store.setCalls.length, 0);
});

test("store 未提供时优雅降级为不限流", async () => {
  const limited = await recordFailedLoginAttempt({ store: undefined, now: FIXED_NOW });
  assert.equal(limited, false);
});

test("store 缺少必要方法时优雅降级为不限流", async () => {
  const limited = await recordFailedLoginAttempt({ store: {}, now: FIXED_NOW });
  assert.equal(limited, false);
});

test("读取失败时优雅降级为不限流，不抛出", async () => {
  const store = new FakeStore();
  store.failGet = true;
  const limited = await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  assert.equal(limited, false);
});

test("写入失败时仍返回 false（放行本次请求），不抛出", async () => {
  const store = new FakeStore();
  store.failSet = true;
  const limited = await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  assert.equal(limited, false);
});

test("桶中数据形状异常时按 0 计数处理，不崩溃", async () => {
  const key = loginAttemptsKey(FIXED_NOW);
  const store = new FakeStore({ [key]: { failedCount: "not-a-number" } });
  const limited = await recordFailedLoginAttempt({ store, now: FIXED_NOW });
  assert.equal(limited, false);
  assert.equal(store.objects.get(key).failedCount, 1);
});
