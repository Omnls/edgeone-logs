/**
 * server/routes/admin-login.js
 *
 * POST /logs-admin-login 的核心逻辑。与 HTTP 框架无关，真实入口在
 * cloud-functions/logs-admin-login/index.js，那里负责解析请求体、设置
 * Set-Cookie 响应头。
 *
 * ─── 设计要点 ─────────────────────────────────────────────────────────
 *
 * 1. 复用既有鉴权原语：管理端密钥仍然是 ADMIN_SHARED_KEY（admin.js 的
 *    ENV_ADMIN_KEY），复用 verifySharedSecret 做固定时间比较，不引入第二套
 *    密钥比较逻辑。
 * 2. 登录成功只签发 session token，不引入任何服务器侧会话状态；token 的
 *    校验与签发都在 server/lib/session.js。
 * 3. 登录失败时先记一次失败计数（尽力而为限流），再返回 401；已达上限则
 *    直接 429，不再进行密钥比较（避免限流形同虚设）。
 * 4. 成功登录不消耗、不重置失败计数器——限流只统计失败尝试。
 */

import { verifySharedSecret } from "../lib/auth.js";
import { ENV_ADMIN_KEY } from "./admin.js";
import { SESSION_TTL_MS, createSessionToken } from "../lib/session.js";
import { recordFailedLoginAttempt } from "../lib/login-rate-limit.js";

/**
 * 请求体里 adminKey 字段允许的最大长度。远高于任何合理密钥长度，只是防止
 * 恶意超长字符串进入比较逻辑之前的粗过滤。
 */
const MAX_ADMIN_KEY_FIELD_LENGTH = 4096;

/**
 * 核心登录处理。
 *
 * @param {object} params
 * @param {string} [params.method]
 * @param {unknown} params.parsedBody 已由入口解析好的 JSON 值（解析失败时传
 *   一个特殊标记，见下方 PARSE_ERROR 用法）；本函数不做 JSON.parse。
 * @param {boolean} params.bodyParseFailed 入口解析 JSON 时是否失败。
 * @param {Record<string, string|undefined>} params.env
 * @param {{ get: Function, setJSON: Function }|undefined} params.store 用于
 *   登录限流计数的存储；仅在失败登录时使用，不用于会话状态。
 * @param {Date} [params.now]
 * @returns {Promise<{ status: number, body: object, sessionToken?: string }>}
 *   成功时 sessionToken 字段带回新签发的 token，由入口写入 Set-Cookie。
 */
export async function handleAdminLoginRequest({
  method = "POST",
  parsedBody,
  bodyParseFailed = false,
  env,
  store,
  now = new Date(),
}) {
  // ─── 1. 方法 ──────────────────────────────────────────────────────
  if (method !== "POST") {
    return {
      status: 405,
      body: { error: "method_not_allowed" },
      headers: { allow: "POST" },
    };
  }

  // ─── 2. 请求体解析结果 ────────────────────────────────────────────
  if (bodyParseFailed) {
    return { status: 400, body: { error: "invalid_json_body" } };
  }
  if (
    typeof parsedBody !== "object" ||
    parsedBody === null ||
    Array.isArray(parsedBody)
  ) {
    return { status: 400, body: { error: "invalid_json_body" } };
  }
  const providedKey = parsedBody.adminKey;
  if (
    typeof providedKey !== "string" ||
    providedKey.length === 0 ||
    providedKey.length > MAX_ADMIN_KEY_FIELD_LENGTH
  ) {
    return { status: 400, body: { error: "missing_admin_key" } };
  }

  // ─── 3. 密钥配置 ──────────────────────────────────────────────────
  const expected = env?.[ENV_ADMIN_KEY];
  if (typeof expected !== "string" || expected.length === 0) {
    return { status: 503, body: { error: "admin_key_not_configured" } };
  }

  // ─── 4. 鉴权 ──────────────────────────────────────────────────────
  const ok = verifySharedSecret(providedKey, expected);
  if (!ok) {
    // 尽力而为限流：先记一次失败，若已达上限则直接 429（且本次未再计入）。
    const limited = await recordFailedLoginAttempt({ store, now });
    if (limited) {
      return { status: 429, body: { error: "too_many_attempts" } };
    }
    return { status: 401, body: { error: "invalid_admin_key" } };
  }

  // ─── 5. 签发会话 token（不重置失败计数器） ────────────────────────
  const sessionToken = createSessionToken({
    secret: expected,
    now,
    ttlMs: SESSION_TTL_MS,
  });
  return { status: 200, body: { ok: true }, sessionToken };
}
