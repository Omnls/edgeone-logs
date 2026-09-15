/**
 * server/lib/login-rate-limit.js
 *
 * 管理端登录失败的「尽力而为」限流。按 UTC 小时分桶计数，存储对象键：
 *   security/login-attempts/<UTC 日期>/<UTC 小时>.json
 * 内容固定为 `{ "failedCount": number }`。
 *
 * ─── 关于并发的一句话说明（刻意不做更多） ─────────────────────────────
 *
 * 这里是「读取 -> 判断 -> 写入」三步，不是原子自增：两个几乎同时到达的失败
 * 请求可能读到同一个旧值、都判定未超限、都写回同一个 +1 后的结果，导致真实
 * 计数比实际失败次数少一次（典型的 TOCTOU 竞态）。Blob store 没有原子自增
 * 原语，为「尽力而为」的防爆破目标引入分布式锁属于过度设计，本模块不做，
 * 也不假装做到了精确计数。
 *
 * ─── 降级策略 ───────────────────────────────────────────────────────────
 *
 * 限流是登录判定之外的附加保护，不是登录本身的必要条件。store 缺失或读写
 * 失败时一律降级为「本次不限流」，绝不因为限流子系统故障而把原本应该拿到
 * 401 的失败登录请求变成 503——那会把一个次要功能的故障放大成主功能不可用。
 */

/** 单个 UTC 小时窗口内允许的失败登录次数上限。 */
export const MAX_FAILED_LOGINS_PER_HOUR = 10;

/**
 * @param {number} n
 * @returns {string}
 */
function pad2(n) {
  return String(n).padStart(2, "0");
}

/**
 * 计算某个时刻所属的限流分桶键。
 *
 * @param {Date} now
 * @returns {string}
 */
export function loginAttemptsKey(now) {
  const d = now instanceof Date ? now : new Date(now);
  const date = `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
  const hour = pad2(d.getUTCHours());
  return `security/login-attempts/${date}/${hour}.json`;
}

/**
 * 记录一次失败的登录尝试，并判断本次是否应当被限流拒绝。
 *
 * 调用方只应在「确认这是一次失败登录」之后调用本函数；成功登录不消耗、
 * 也不重置计数器。
 *
 * @param {object} params
 * @param {{ get: Function, setJSON: Function }|undefined} params.store
 * @param {Date} [params.now]
 * @returns {Promise<boolean>} true 表示已达上限，本次应返回 429（且未写入）；
 *   false 表示未达上限（已计入本次失败，或因存储不可用而降级放行）。
 */
export async function recordFailedLoginAttempt({ store, now = new Date() }) {
  if (!store || typeof store.get !== "function" || typeof store.setJSON !== "function") {
    // 没有可用存储：不阻塞登录判定，降级为不限流。
    return false;
  }

  const key = loginAttemptsKey(now);

  let bucket;
  try {
    bucket = await store.get(key, { type: "json", consistency: "strong" });
  } catch {
    // 读失败：无法确定当前计数，降级放行本次请求。
    return false;
  }

  const failedCount =
    bucket &&
    typeof bucket === "object" &&
    typeof bucket.failedCount === "number" &&
    Number.isFinite(bucket.failedCount) &&
    bucket.failedCount >= 0
      ? bucket.failedCount
      : 0;

  if (failedCount >= MAX_FAILED_LOGINS_PER_HOUR) {
    // 已达上限：不写入（避免无界增长），直接判定限流。
    return true;
  }

  try {
    await store.setJSON(key, { failedCount: failedCount + 1 });
  } catch {
    // 写失败：仍按未超限放行本次请求（由调用方返回 401），不阻塞登录。
  }
  return false;
}
