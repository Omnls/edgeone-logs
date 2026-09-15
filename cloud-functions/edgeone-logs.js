/**
 * cloud-functions/edgeone-logs.js
 *
 * POST /edgeone-logs 的真实 EdgeOne Pages Cloud Function 入口。
 *
 * 依据官方 https://pages.edgeone.ai/document/node-functions：Node Functions
 * 放在 `cloud-functions/` 目录下，默认导出 `onRequest(context)`，context 中
 * 含 request 与 env；文件名决定路由路径，因此本文件对应 /edgeone-logs。
 *
 * ─── 处理顺序 ─────────────────────────────────────────────────────────
 *
 * 方法、Content-Encoding、密钥配置与鉴权全部在读取请求正文之前完成：未通过
 * 鉴权的请求不应该消耗读流带宽与函数内存。通过鉴权后才有界读取正文，读满
 * 上限立即取消上游流。
 *
 * 这里不接受任何来自请求上下文的 store 注入。生产路径只能是
 * getLogStore(env)，不存在测试后门。
 */

import {
  BodyTooLargeError,
  jsonResponse,
  readBoundedBody,
} from "../server/lib/http.js";
import {
  DEFAULT_MAX_INGEST_BODY_BYTES,
  INGEST_KEY_HEADER,
  authorizeIngest,
  handleIngestRequest,
} from "../server/routes/ingest.js";
import { getLogStore } from "../server/storage/get-store.js";

/**
 * @param {{ request: Request, env: Record<string,string|undefined> }} context
 * @returns {Promise<Response>}
 */
export async function onRequest(context) {
  const request = context.request;
  const env = context.env ?? {};

  let url;
  try {
    url = new URL(request.url);
  } catch {
    return jsonResponse(400, { error: "invalid_request_url" });
  }

  const contentEncoding = request.headers.get("content-encoding") ?? undefined;

  // 鉴权先行：方法、编码、配置与密钥都在读正文之前判定。
  const auth = authorizeIngest({
    method: request.method,
    contentEncoding,
    requestPath: url.pathname,
    queryParams: url.searchParams,
    ingestKeyHeader: request.headers.get(INGEST_KEY_HEADER) ?? undefined,
    env,
  });
  if (!auth.ok) {
    return jsonResponse(auth.status, auth.body, auth.headers);
  }

  // 通过鉴权后才取 store：未授权请求不触发任何凭据交换。
  let store;
  try {
    store = getLogStore(env);
  } catch {
    // store 名非法，或运行环境缺少 Pages Blob 凭据。属于部署配置问题，
    // 不回显底层异常信息。
    return jsonResponse(503, { error: "storage_not_configured" });
  }

  let rawBody;
  try {
    rawBody = await readBoundedBody(request, DEFAULT_MAX_INGEST_BODY_BYTES);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return jsonResponse(413, {
        error: "payload_too_large",
        maxBytes: err.maxBytes,
      });
    }
    return jsonResponse(400, { error: "body_read_failed" });
  }

  let result;
  try {
    result = await handleIngestRequest({
      method: request.method,
      rawBody,
      contentEncoding,
      requestPath: url.pathname,
      queryParams: url.searchParams,
      ingestKeyHeader: request.headers.get(INGEST_KEY_HEADER) ?? undefined,
      env,
      store,
    });
  } catch {
    // 兜底：任何未预期异常都不能把堆栈或正文片段带给调用方。
    return jsonResponse(500, { error: "internal_error" });
  }

  return jsonResponse(result.status, result.body, result.headers);
}

export default onRequest;
