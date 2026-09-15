/**
 * cloud-functions/logs-admin-logout/index.js
 *
 * POST /logs-admin-logout 的真实 EdgeOne Pages Cloud Function 入口。
 *
 * 依据官方 https://pages.edgeone.ai/document/node-functions：目录下的
 * index.js 对应该目录路径本身，因此本文件对应 /logs-admin-logout。
 *
 * ─── 设计要点 ─────────────────────────────────────────────────────────
 *
 * 退出登录不需要任何身份校验：无论请求带的 cookie 是否有效、是否存在，
 * 目的都是让客户端浏览器清除它。用一个已过期（Max-Age=0）的同名 Set-Cookie
 * 覆盖即可，服务端本身不持有任何 session 状态（session.js 头部注释），
 * 因此这里没有「注销」可做，只是清 cookie。
 *
 * 不做业务判断，因此不需要经过 server/routes/ 下的框架无关核心逻辑层——
 * 这个端点本身就只有“方法校验 + 清 cookie”两步，没有必要为它单独抽一层。
 */

import { jsonResponse } from "../../server/lib/http.js";
import { SESSION_COOKIE_NAME } from "../../server/lib/session.js";

/**
 * @param {{ request: Request, env: Record<string,string|undefined> }} context
 * @returns {Promise<Response>}
 */
export async function onRequest(context) {
  const request = context.request;

  if (request.method !== "POST") {
    return jsonResponse(405, { error: "method_not_allowed" }, { allow: "POST" });
  }

  return jsonResponse(200, { ok: true }, {
    "set-cookie": `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`,
  });
}

export default onRequest;
