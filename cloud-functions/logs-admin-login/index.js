/**
 * cloud-functions/logs-admin-login/index.js
 *
 * POST /logs-admin-login 的真实 EdgeOne Pages Cloud Function 入口。
 *
 * 依据官方 https://pages.edgeone.ai/document/node-functions：目录下的
 * index.js 对应该目录路径本身，因此本文件对应 /logs-admin-login。
 *
 * 与其他入口一样，这里只做“框架相关的搬运”：解析方法/正文/构造 Set-Cookie，
 * 业务判断（校验密钥、限流、签发 token）全部在
 * server/routes/admin-login.js 的 handleAdminLoginRequest 中完成，本文件不
 * 重复任何判断逻辑。
 *
 * ─── Set-Cookie 属性 ────────────────────────────────────────────────────
 *
 * HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=<SESSION_TTL_MS 对应秒数>
 *
 * 只有 handleAdminLoginRequest 返回 sessionToken（即校验通过）时才设置该头；
 * 401/429/等失败响应不带 Set-Cookie。
 *
 * 正文解析失败（包括非 JSON、空正文）不抛错，而是转换成
 * bodyParseFailed:true 交给业务层判 400，保持“入口不因畸形输入 500”的
 * 项目惯例。
 */

import {
  BodyTooLargeError,
  jsonResponse,
  readBoundedBody,
} from "../../server/lib/http.js";
import { handleAdminLoginRequest } from "../../server/routes/admin-login.js";
import { SESSION_COOKIE_NAME, SESSION_TTL_MS } from "../../server/lib/session.js";
import { getLogStore } from "../../server/storage/get-store.js";

/** 登录请求正文的字节上限（自设，远大于一个 JSON key 所需，避免误伤）。 */
const MAX_LOGIN_BODY_BYTES = 16 * 1024;

/**
 * @param {{ request: Request, env: Record<string,string|undefined> }} context
 * @returns {Promise<Response>}
 */
export async function onRequest(context) {
  const request = context.request;
  const env = context.env ?? {};

  if (request.method !== "POST") {
    return jsonResponse(405, { error: "method_not_allowed" }, { allow: "POST" });
  }

  // store 用于登录失败限流；限流子系统的降级策略在 recordFailedLoginAttempt
  // 内部处理，这里即便取不到 store 也不能因此让登录本身失败。
  let store;
  try {
    store = getLogStore(env);
  } catch {
    store = undefined;
  }

  let parsedBody;
  let bodyParseFailed = false;
  try {
    const raw = await readBoundedBody(request, MAX_LOGIN_BODY_BYTES);
    parsedBody = JSON.parse(raw.toString("utf8"));
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return jsonResponse(413, { error: "payload_too_large", maxBytes: err.maxBytes });
    }
    bodyParseFailed = true;
  }

  let result;
  try {
    result = await handleAdminLoginRequest({
      method: request.method,
      parsedBody,
      bodyParseFailed,
      env,
      store,
    });
  } catch {
    return jsonResponse(500, { error: "internal_error" });
  }

  const extraHeaders = { ...(result.headers ?? {}) };
  if (typeof result.sessionToken === "string" && result.sessionToken.length > 0) {
    const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
    extraHeaders["set-cookie"] =
      `${SESSION_COOKIE_NAME}=${result.sessionToken}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}`;
  }

  return jsonResponse(result.status, result.body, extraHeaders);
}

export default onRequest;
