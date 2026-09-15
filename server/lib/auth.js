/**
 * server/lib/auth.js
 *
 * Authentication helpers for the ingest and admin HTTP endpoints.
 *
 * Two independent mechanisms are implemented here:
 *
 * 1. EdgeOne's own `auth_key`/`access_key` signature scheme (verifyEdgeOneSignature),
 *    used ONLY when the EdgeOne console has "加密签名" (encrypted signature)
 *    enabled for a push task. Documented in docs/reference/61296.md, section
 *    "请求鉴权算法". This module implements exactly the algorithm described
 *    there — nothing has been guessed or extrapolated beyond that document.
 *
 * 2. A constant-time shared-secret comparison (constantTimeEqual /
 *    verifySharedSecret), used for this project's OWN independent ingest key
 *    and admin key. These are NOT part of any EdgeOne-documented protocol —
 *    they are this project's own fail-closed gate, required in addition to
 *    (1), never instead of it.
 *
 * ─── Why two layers for ingest ────────────────────────────────────────────
 *
 * EdgeOne's signature scheme is OPTIONAL from EdgeOne's point of view — the
 * console push task may or may not have "加密签名" turned on. If it is off,
 * requests arrive with no auth_key/access_key at all. This module's caller
 * (server/routes/ingest.js) must NOT treat "EdgeOne signature absent" as
 * "no auth needed" — per the phase-2 handoff brief, an independent ingest
 * key (checked here via verifySharedSecret) is REQUIRED on every request,
 * regardless of whether the EdgeOne signature is present. When the EdgeOne
 * signature IS present, both checks must pass.
 *
 * ─── 官方示例与其中的文档错误（61296.md:156-172） ─────────────────────
 *
 *   SecretId = "YourID", SecretKey = "YourKey"
 *   uri = "/access_log/post", timestamp = 1571587200, rand = 0
 *   string_to_sign = "/access_log/post-1571587200-0-YourKey"
 *
 * 文档给出的 md5hash 是 "1f7ffa7bff8f06bbfbe2ace0f14b7e16"，但该字符串真实的
 * MD5 是 "d8079ca27f0db9157de64061e7264b8e"（本项目独立复算确认，两次结果一致）。
 * 因此文档示例哈希值有误，本模块实现的是文档描述的**算法**
 * md5(uri-timestamp-rand-SecretKey)，而不是照抄它印错的结果值；
 * tests/auth.test.js 断言的是复算出的真实值。
 *
 * 同一份文档里还有一处前后不一致：示例说明中 uri 为 `/access_log/post`，
 * 但最终推送 URL 示例写成了 `/cdnlog/post`。实现按**真实请求路径**计算签名，
 * 不硬编码任何示例路径。
 */

import { createHash, timingSafeEqual } from "node:crypto";

/** Default replay-window tolerance in seconds, per 61296.md's suggestion. */
export const DEFAULT_MAX_SKEW_SECONDS = 300;

/**
 * Compute the EdgeOne auth_key md5 hash for a given uri/timestamp/rand/secret.
 *
 * string_to_sign = `${uri}-${timestamp}-${rand}-${secretKey}`
 * returns the lowercase hex md5 of that string, exactly as documented.
 *
 * @param {object} params
 * @param {string} params.uri - request path only (no query string), e.g. "/access_log/post".
 * @param {string} params.timestamp - the timestamp segment from auth_key, as a string of digits.
 * @param {string} params.rand - the rand segment from auth_key, as-received (not re-validated for "randomness").
 * @param {string} params.secretKey - the SecretKey looked up for the request's access_key (SecretId).
 * @returns {string} lowercase hex md5 digest
 */
export function computeSignature({ uri, timestamp, rand, secretKey }) {
  const stringToSign = `${uri}-${timestamp}-${rand}-${secretKey}`;
  return createHash("md5").update(stringToSign, "utf8").digest("hex");
}

/**
 * Constant-time comparison of two strings, safe against timing side-channels.
 *
 * `crypto.timingSafeEqual` throws if the two buffers differ in length, and a
 * naive "check length first, bail early" wrapper would itself leak timing
 * information correlated with length. To avoid that, when lengths differ we
 * still perform a fixed-cost timingSafeEqual call (against a same-length
 * padded/truncated buffer) before returning false, so the function's timing
 * does not trivially reveal "lengths differed" vs "lengths matched but
 * content didn't".
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    // Perform a same-cost dummy comparison so this branch's timing profile
    // resembles the equal-length path, rather than returning immediately.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

/**
 * Verify an EdgeOne `auth_key`/`access_key` signature pair.
 *
 * Fails closed on every ambiguous or missing input — never treats "could not
 * determine" as "allow". Never leaks which specific sub-check failed to the
 * caller beyond the returned `reason` (callers must not echo `reason` in the
 * HTTP response body to an untrusted client; it is for internal logging only).
 *
 * @param {object} params
 * @param {string} params.uri - request path only (no query string).
 * @param {string|undefined} params.authKey - raw `auth_key` query param value.
 * @param {string|undefined} params.accessKey - raw `access_key` query param value.
 * @param {(accessKey: string) => (string|undefined)} params.getSecretKey - looks
 *   up the SecretKey configured for a given SecretId (access_key). Must return
 *   `undefined` for unknown access keys — this function will fail closed.
 * @param {number} [params.nowSeconds] - current time in Unix seconds. Defaults
 *   to `Math.floor(Date.now() / 1000)`. Overridable for deterministic tests.
 * @param {number} [params.maxSkewSeconds] - replay window; defaults to 300s
 *   per 61296.md's suggested expiry.
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function verifyEdgeOneSignature({
  uri,
  authKey,
  accessKey,
  getSecretKey,
  nowSeconds = Math.floor(Date.now() / 1000),
  maxSkewSeconds = DEFAULT_MAX_SKEW_SECONDS,
}) {
  if (typeof uri !== "string" || uri.length === 0) {
    return { ok: false, reason: "missing_uri" };
  }
  if (typeof authKey !== "string" || authKey.length === 0) {
    return { ok: false, reason: "missing_auth_key" };
  }
  if (typeof accessKey !== "string" || accessKey.length === 0) {
    return { ok: false, reason: "missing_access_key" };
  }

  // auth_key = "{timestamp}-{rand}-{md5hash}" — split into exactly 3 parts.
  // rand itself is not required to be numeric/free of hyphens by the spec,
  // but the documented examples use plain digits, and the official Python/Go
  // reference implementations both split on "-" expecting exactly 3 parts.
  // We follow that same convention: split into exactly 3 segments.
  const parts = authKey.split("-");
  if (parts.length !== 3) {
    return { ok: false, reason: "malformed_auth_key" };
  }
  const [timestampStr, rand, md5hash] = parts;

  if (!/^\d{1,10}$/.test(timestampStr)) {
    return { ok: false, reason: "malformed_timestamp" };
  }
  if (rand.length === 0) {
    return { ok: false, reason: "malformed_rand" };
  }
  if (!/^[0-9a-f]{32}$/i.test(md5hash)) {
    return { ok: false, reason: "malformed_md5hash" };
  }

  const timestamp = Number(timestampStr);
  if (!Number.isFinite(timestamp)) {
    return { ok: false, reason: "malformed_timestamp" };
  }
  if (Math.abs(nowSeconds - timestamp) > maxSkewSeconds) {
    return { ok: false, reason: "timestamp_expired" };
  }

  const secretKey = getSecretKey(accessKey);
  if (typeof secretKey !== "string" || secretKey.length === 0) {
    return { ok: false, reason: "unknown_access_key" };
  }

  const expected = computeSignature({
    uri,
    timestamp: timestampStr,
    rand,
    secretKey,
  });

  if (!constantTimeEqual(expected.toLowerCase(), md5hash.toLowerCase())) {
    return { ok: false, reason: "signature_mismatch" };
  }

  return { ok: true };
}

/**
 * Verify a request-supplied shared secret (this project's own independent
 * ingest key or admin key) against a configured expected value.
 *
 * Fails closed: missing configured value, missing provided value, or a
 * mismatch are all treated identically as failure. Never throws.
 *
 * @param {string|undefined} provided - value from the request (e.g. header).
 * @param {string|undefined} expected - value from environment configuration.
 * @returns {boolean}
 */
export function verifySharedSecret(provided, expected) {
  if (typeof expected !== "string" || expected.length === 0) return false;
  if (typeof provided !== "string" || provided.length === 0) return false;
  return constantTimeEqual(provided, expected);
}
