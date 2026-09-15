/**
 * server/lib/session.js
 *
 * 无状态 session token：登录成功后下发，之后 /logs-admin 查询接口可以只靠
 * cookie 免带 X-Admin-Key。
 *
 * 这是无服务器环境，不能假设同一实例后续请求还在，因此这里不持有任何服务端
 * 会话状态——token 本身就是全部凭证，每次请求都由服务端重新验证签名与有效期，
 * 不查任何「会话表」。
 *
 * ─── token 格式 ─────────────────────────────────────────────────────────
 *
 *   `${base64url(payloadJson)}.${base64url(hmacSha256(payloadB64, secret))}`
 *
 * payload 只含过期时间戳（毫秒）：`{ "exp": <number> }`。密钥固定用
 * ADMIN_SHARED_KEY——登录密钥与 session 签名密钥共用同一份配置，不新增
 * 环境变量，同时保证「知道 ADMIN_SHARED_KEY 才能签发/验证 token」。
 *
 * 签名比较使用 server/lib/auth.js 里已有的 constantTimeEqual（基于
 * crypto.timingSafeEqual 的固定时间比较），不用字符串 `===`，避免时序旁路。
 */

import { createHmac } from "node:crypto";
import { constantTimeEqual } from "./auth.js";

/** session token 有效期：12 小时。 */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

/** session cookie 名。 */
export const SESSION_COOKIE_NAME = "eo_admin_session";

/** base64url 字符集，token 的两段都必须只含这些字符。 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * @param {Buffer} buf
 * @returns {string}
 */
function base64urlEncode(buf) {
  return Buffer.from(buf).toString("base64url");
}

/**
 * 计算 payload 段的 HMAC-SHA256，以 base64url 编码返回。
 *
 * @param {string} payloadB64
 * @param {string} secret
 * @returns {string}
 */
function computeHmacB64(payloadB64, secret) {
  return base64urlEncode(createHmac("sha256", secret).update(payloadB64, "utf8").digest());
}

/**
 * 生成 session token。
 *
 * @param {object} params
 * @param {string} params.secret HMAC 密钥（ADMIN_SHARED_KEY 的值）。
 * @param {Date|number} [params.now] 当前时间，默认 Date.now()；可覆盖用于测试。
 * @param {number} [params.ttlMs] 有效期毫秒数，默认 12 小时。
 * @returns {string}
 */
export function createSessionToken({ secret, now, ttlMs = SESSION_TTL_MS }) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new TypeError("secret must be a non-empty string");
  }
  if (typeof ttlMs !== "number" || !Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new TypeError("ttlMs must be a positive finite number");
  }
  const nowMs = now instanceof Date ? now.getTime() : typeof now === "number" ? now : Date.now();
  const exp = nowMs + ttlMs;
  const payloadB64 = base64urlEncode(Buffer.from(JSON.stringify({ exp }), "utf8"));
  const hmacB64 = computeHmacB64(payloadB64, secret);
  return `${payloadB64}.${hmacB64}`;
}

/**
 * 校验 session token。
 *
 * 任何格式错误、签名不符、密钥不匹配、已过期都返回 false，绝不抛出异常——
 * 调用方（cookie 鉴权路径）不应该因为收到一个畸形 cookie 而 500。
 *
 * @param {object} params
 * @param {string|undefined} params.token
 * @param {string|undefined} params.secret
 * @param {Date|number} [params.now]
 * @returns {boolean}
 */
export function verifySessionToken({ token, secret, now }) {
  try {
    if (typeof token !== "string" || token.length === 0) return false;
    if (typeof secret !== "string" || secret.length === 0) return false;

    const dotIndex = token.indexOf(".");
    if (dotIndex === -1 || token.indexOf(".", dotIndex + 1) !== -1) {
      // 必须恰好一个分隔符：零个或多个都是畸形 token。
      return false;
    }
    const payloadB64 = token.slice(0, dotIndex);
    const hmacB64 = token.slice(dotIndex + 1);
    if (payloadB64.length === 0 || hmacB64.length === 0) return false;
    if (!BASE64URL_PATTERN.test(payloadB64) || !BASE64URL_PATTERN.test(hmacB64)) return false;

    const expectedHmacB64 = computeHmacB64(payloadB64, secret);
    if (!constantTimeEqual(hmacB64, expectedHmacB64)) return false;

    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
    } catch {
      return false;
    }
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return false;
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) return false;

    const nowMs = now instanceof Date ? now.getTime() : typeof now === "number" ? now : Date.now();
    return nowMs < payload.exp;
  } catch {
    return false;
  }
}
