/**
 * server/lib/parse-log-body.js
 *
 * 把 EdgeOne 实时日志推送请求的原始字节解析为普通对象数组。
 *
 * 支持的正文形态（均来自官方文档，不含猜测）：
 *   - JSON Lines / NDJSON：默认格式（docs/reference/64485.md）。
 *   - 多行缩进的单个 JSON 对象：控制台连通性校验样例
 *     （docs/reference/61296.md:39-64）。
 *   - JSON 数组：自定义格式下可能出现的批次包装。
 *   - 以上三者的 gzip 压缩形态（Content-Encoding: gzip，由调用方读取请求头
 *     后显式告知，不嗅探魔数）。
 *
 * CSV 与任意自定义包装格式不支持：会被明确拒绝，而不是被猜测解析。项目文档
 * 要求控制台保持默认的 JSON Lines。
 *
 * ─── 错误容忍契约 ───────────────────────────────────────────────────
 *
 * 任一非空行或数组元素不是合法 JSON 对象，整批拒绝，零记录返回。
 * 不做「跳过坏行、确认其余」：那会让投递方以为整批已成功接收，坏行数据
 * 永久丢失且无法回放。
 *
 * ─── 有界性 ─────────────────────────────────────────────────────────
 *
 * 解压后字节数、记录总条数、单条记录嵌套深度都有上限，且深度检查在任何
 * 递归处理（脱敏、规范化）之前完成，避免深层嵌套正文在后续阶段耗尽栈或
 * 内存。这些都是本项目自设的防御性上限，不是平台限制。
 */

import { gunzipSync } from "node:zlib";

/** gzip 解压后的自设上限，防止解压炸弹耗尽函数内存。非平台限制。 */
export const DEFAULT_MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024;

/** 单次投递的记录总条数上限。自设值。 */
export const DEFAULT_MAX_RECORDS = 5000;

/**
 * 单条记录允许的最大嵌套深度。顶层对象记作深度 1。
 *
 * 官方预设字段都是标量，正常日志深度为 1；自定义字段可能带浅层嵌套结构。
 * 32 远高于任何合理取值，只用于拦截恶意构造的深层正文。自设值。
 */
export const DEFAULT_MAX_DEPTH = 32;

/** 稳定的错误分类码，供路由层映射为固定的 HTTP 响应分类。 */
export const LOG_BODY_ERROR_CODES = Object.freeze({
  EMPTY_BODY: "empty_body",
  GZIP_FAILED: "gzip_failed",
  GZIP_TOO_LARGE: "gzip_too_large",
  INVALID_RECORD: "invalid_record",
  UNSUPPORTED_BODY: "unsupported_body",
  TOO_MANY_RECORDS: "too_many_records",
  RECORD_TOO_DEEP: "record_too_deep",
});

/**
 * 解析失败时抛出的错误。`code` 为上表中的稳定分类；`detail` 只用于本地
 * 排查，调用方不得把它回显给不可信客户端。
 */
export class LogBodyError extends Error {
  /**
   * @param {string} code
   * @param {string} detail
   */
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.name = "LogBodyError";
    this.code = code;
    this.detail = detail;
  }
}

/**
 * @typedef {object} ParseResult
 * @property {Record<string, unknown>[]} records 解析出的记录，顺序与正文一致。
 * @property {'ndjson'|'single-object'|'json-array'} kind 实际识别到的正文形态。
 * @property {number} decompressedBytes 解压后（或原始）正文字节数。
 */

/**
 * @param {Buffer} rawBody 原始请求正文字节（可能是 gzip 压缩后的）。
 * @param {object} [options]
 * @param {boolean} [options.gzip] 是否声明了 Content-Encoding: gzip。只按调用
 *   方读取到的请求头决定，不嗅探 gzip 魔数：未声明却压缩的正文会正常地解析
 *   失败，而不是被静默猜测。
 * @param {number} [options.maxDecompressedBytes] 解压后字节上限。
 * @param {number} [options.maxRecords] 记录总条数上限。
 * @param {number} [options.maxDepth] 单条记录嵌套深度上限。
 * @returns {ParseResult}
 * @throws {LogBodyError}
 */
export function parseLogBody(rawBody, options = {}) {
  const {
    gzip = false,
    maxDecompressedBytes = DEFAULT_MAX_DECOMPRESSED_BYTES,
    maxRecords = DEFAULT_MAX_RECORDS,
    maxDepth = DEFAULT_MAX_DEPTH,
  } = options;

  let buf = rawBody;
  if (gzip) {
    try {
      buf = gunzipSync(rawBody, { maxOutputLength: maxDecompressedBytes });
    } catch (err) {
      // zlib 在超出 maxOutputLength 时抛 ERR_BUFFER_TOO_LARGE，其余为数据损坏。
      const code =
        err && err.code === "ERR_BUFFER_TOO_LARGE"
          ? LOG_BODY_ERROR_CODES.GZIP_TOO_LARGE
          : LOG_BODY_ERROR_CODES.GZIP_FAILED;
      // 不把 zlib 原始错误信息带进 detail，避免正文片段进入日志。
      throw new LogBodyError(code, "gzip payload could not be decompressed");
    }
  }

  if (buf.length > maxDecompressedBytes) {
    throw new LogBodyError(
      LOG_BODY_ERROR_CODES.GZIP_TOO_LARGE,
      "body exceeds decompressed size limit"
    );
  }

  const text = buf.toString("utf8");
  if (text.trim().length === 0) {
    throw new LogBodyError(LOG_BODY_ERROR_CODES.EMPTY_BODY, "body is empty");
  }

  const parsed = parseText(text, maxRecords);

  // 深度检查放在返回之前、任何递归处理（脱敏/规范化）之前。
  for (let i = 0; i < parsed.records.length; i += 1) {
    assertDepthWithin(parsed.records[i], maxDepth, i);
  }

  return {
    records: parsed.records,
    kind: parsed.kind,
    decompressedBytes: buf.length,
  };
}

/**
 * 按正文文本决定形态并解析。
 *
 * 先尝试整体 JSON 文档：官方连通性校验样例是多行缩进的单个对象，按行数
 * 判定会把它误当作 NDJSON。整体解析失败才按 JSON Lines 逐行处理。
 *
 * @param {string} text
 * @param {number} maxRecords
 * @returns {{ records: Record<string, unknown>[], kind: 'ndjson'|'single-object'|'json-array' }}
 */
function parseText(text, maxRecords) {
  let whole;
  let wholeOk = true;
  try {
    whole = JSON.parse(text);
  } catch {
    wholeOk = false;
  }

  if (wholeOk) {
    if (Array.isArray(whole)) {
      if (whole.length > maxRecords) {
        throw new LogBodyError(
          LOG_BODY_ERROR_CODES.TOO_MANY_RECORDS,
          `array has ${whole.length} elements, limit is ${maxRecords}`
        );
      }
      const records = [];
      for (let i = 0; i < whole.length; i += 1) {
        if (!isPlainRecord(whole[i])) {
          throw new LogBodyError(
            LOG_BODY_ERROR_CODES.INVALID_RECORD,
            `array element ${i} is not a JSON object`
          );
        }
        records.push(whole[i]);
      }
      if (records.length === 0) {
        throw new LogBodyError(
          LOG_BODY_ERROR_CODES.EMPTY_BODY,
          "array contains no records"
        );
      }
      return { records, kind: "json-array" };
    }
    if (isPlainRecord(whole)) {
      return { records: [whole], kind: "single-object" };
    }
    // 合法 JSON 但既不是对象也不是数组（数字、字符串、null 等）。
    throw new LogBodyError(
      LOG_BODY_ERROR_CODES.UNSUPPORTED_BODY,
      "body is a JSON scalar, not a log record or record array"
    );
  }

  // 整体解析失败：按 JSON Lines 逐行解析。任一非空行非法即整批失败。
  const records = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.trim().length === 0) continue;

    if (records.length >= maxRecords) {
      throw new LogBodyError(
        LOG_BODY_ERROR_CODES.TOO_MANY_RECORDS,
        `body has more than ${maxRecords} records`
      );
    }

    let value;
    try {
      value = JSON.parse(line);
    } catch {
      // 只报行号，不回显行内容，避免把日志正文写进错误链路。
      throw new LogBodyError(
        LOG_BODY_ERROR_CODES.INVALID_RECORD,
        `line ${i + 1} is not valid JSON`
      );
    }
    if (!isPlainRecord(value)) {
      throw new LogBodyError(
        LOG_BODY_ERROR_CODES.INVALID_RECORD,
        `line ${i + 1} is not a JSON object`
      );
    }
    records.push(value);
  }

  if (records.length === 0) {
    throw new LogBodyError(
      LOG_BODY_ERROR_CODES.EMPTY_BODY,
      "body contains no records"
    );
  }

  return { records, kind: "ndjson" };
}

/**
 * 迭代式深度检查（不递归，避免检查本身就把栈打爆）。
 *
 * @param {unknown} record
 * @param {number} maxDepth
 * @param {number} index 记录序号，仅用于 detail 中的定位，不回显内容。
 */
function assertDepthWithin(record, maxDepth, index) {
  /** @type {{ value: unknown, depth: number }[]} */
  const stack = [{ value: record, depth: 1 }];
  while (stack.length > 0) {
    const { value, depth } = stack.pop();
    if (value === null || typeof value !== "object") continue;
    if (depth > maxDepth) {
      throw new LogBodyError(
        LOG_BODY_ERROR_CODES.RECORD_TOO_DEEP,
        `record ${index} nests deeper than ${maxDepth} levels`
      );
    }
    const children = Array.isArray(value) ? value : Object.values(value);
    for (const child of children) {
      if (child !== null && typeof child === "object") {
        stack.push({ value: child, depth: depth + 1 });
      }
    }
  }
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
