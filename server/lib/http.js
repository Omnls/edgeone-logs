/**
 * server/lib/http.js
 *
 * 统一构造函数响应。所有响应（含错误）都必须带上：
 *   - Content-Type: application/json; charset=utf-8
 *   - Cache-Control: no-store（日志接口与查询结果都不允许被边缘或浏览器缓存）
 *   - X-Content-Type-Options: nosniff
 *   - Referrer-Policy: no-referrer
 *
 * edgeone.json 里的 headers 规则只覆盖静态资源，不保证覆盖函数响应，
 * 因此函数自身必须显式设置这些头，不依赖平台配置。
 */

/** 所有 JSON 响应共用的安全与缓存头。 */
export const BASE_HEADERS = Object.freeze({
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
});

/**
 * 构造 JSON 响应。
 *
 * @param {number} status HTTP 状态码。
 * @param {unknown} body 可 JSON 序列化的响应体。
 * @param {Record<string,string>} [extraHeaders] 附加响应头（例如 405 的 Allow）。
 * @returns {Response}
 */
export function jsonResponse(status, body, extraHeaders) {
  const headers = { ...BASE_HEADERS, ...(extraHeaders ?? {}) };
  return new Response(JSON.stringify(body), { status, headers });
}

/** 读流超限时抛出的错误。 */
export class BodyTooLargeError extends Error {
  /**
   * @param {number} maxBytes
   */
  constructor(maxBytes) {
    super(`request body exceeds ${maxBytes} bytes`);
    this.name = "BodyTooLargeError";
    this.code = "BODY_TOO_LARGE";
    this.maxBytes = maxBytes;
  }
}

/**
 * 有界读取请求正文。
 *
 * 不信任 Content-Length：该头可以缺失、也可以与实际字节数不符，按它预分配或
 * 提前放行都不安全。这里边读边累计，一旦超过上限立即取消上游流并抛错，避免
 * 把超大正文整体读进内存。
 *
 * 没有可读流时（某些运行时只提供 arrayBuffer），退回一次性读取后再校验大小：
 * 此时无法提前中断，但仍然不会把超限正文交给后续处理。
 *
 * @param {Request} request
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 * @throws {BodyTooLargeError}
 */
export async function readBoundedBody(request, maxBytes) {
  const body = request.body;
  if (!body || typeof body.getReader !== "function") {
    const buf = Buffer.from(await request.arrayBuffer());
    if (buf.length > maxBytes) throw new BodyTooLargeError(maxBytes);
    return buf;
  }

  const reader = body.getReader();
  /** @type {Buffer[]} */
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined || value === null) continue;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maxBytes) {
        // 主动取消，不再继续接收剩余字节。
        try {
          await reader.cancel();
        } catch {
          // 取消失败不影响结论：本次请求一律按超限处理。
        }
        throw new BodyTooLargeError(maxBytes);
      }
      chunks.push(chunk);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // 已取消或已释放时忽略。
    }
  }
  return Buffer.concat(chunks, total);
}
