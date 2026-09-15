/**
 * cloud-functions/logs-admin/index.js
 *
 * GET /logs-admin 的真实 EdgeOne Pages Cloud Function 入口。
 *
 * 依据官方 https://pages.edgeone.ai/document/node-functions：目录下的
 * index.js 对应该目录路径本身，因此本文件对应 /logs-admin。
 *
 * 与 ingest 入口一样，这里只做数据搬运与 Store 获取，不做业务判断，
 * 也不接受任何来自请求上下文的 store 注入。
 */

import { jsonResponse } from "../../server/lib/http.js";
import {
  ADMIN_KEY_HEADER,
  handleAdminRequest,
} from "../../server/routes/admin.js";
import { getLogStore } from "../../server/storage/get-store.js";

/**
 * @param {{ request: Request, env: Record<string,string|undefined> }} context
 * @returns {Promise<Response>}
 */
export async function onRequest(context) {
  const request = context.request;
  const env = context.env ?? {};

  if (request.method !== "GET") {
    return jsonResponse(405, { error: "method_not_allowed" }, { allow: "GET" });
  }

  let store;
  try {
    store = getLogStore(env);
  } catch {
    return jsonResponse(503, { error: "storage_not_configured" });
  }

  const q = new URL(request.url).searchParams;
  const raw = (name) => q.get(name) ?? undefined;

  let result;
  try {
    result = await handleAdminRequest({
      method: request.method,
      adminKeyHeader: request.headers.get(ADMIN_KEY_HEADER) ?? undefined,
      env,
      store,
      date: raw("date"),
      hour: raw("hour"),
      // 这里原样传字符串，由业务层做严格校验：非法参数必须 400，
      // 不能在入口悄悄转成 undefined 而放宽筛选条件。
      status: raw("status"),
      statusMin: raw("statusMin"),
      statusMax: raw("statusMax"),
      requestHost: raw("host"),
      requestId: raw("requestId"),
      limit: raw("limit"),
      cursor: raw("cursor"),
    });
  } catch {
    return jsonResponse(500, { error: "internal_error" });
  }

  return jsonResponse(result.status, result.body, result.headers);
}

export default onRequest;
