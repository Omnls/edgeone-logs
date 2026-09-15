/**
 * server/routes/admin.js
 *
 * GET /logs-admin 管理端检索的核心逻辑。真实入口在
 * cloud-functions/logs-admin/index.js，本文件只导出与框架无关的纯函数。
 *
 * ─── 设计要点 ─────────────────────────────────────────────────────
 *
 * 1. 单分区严格限定：每次查询只扫描 `logs/<date>/<hour>/` 一个前缀，不做
 *    跨小时自动聚合。跨小时排查由调用方按小时分别查询后自行合并。
 * 2. 读取与响应双预算：SDK 的 get 会把整个对象先缓冲进内存（见
 *    node_modules/@edgeone/pages-blob/dist/index.js 中 getObject 的实现），
 *    因此不匹配的记录同样消耗内存与带宽，必须计入累计读取预算，而不是只
 *    对最终返回的内容计量。响应预算另行按完整序列化结果计量。
 * 3. 失败绝不伪装成零结果：列举失败、读取失败、对象缺失、schema 不符一律
 *    显式 5xx。返回 200 且 matchedRecords=0 只能表示「这一页确实没有匹配」。
 * 4. 显式空取值的参数视为非法：`?host=` 这类写法通常是调用方拼接出错，
 *    静默忽略会让人以为筛选生效了，实际却返回了更多日志。
 */

import { verifySharedSecret } from "../lib/auth.js";
import {
  BATCH_SCHEMA_VERSION,
  getBatch,
  listBatches,
} from "../storage/batch-store.js";

/** 环境变量名：管理端独立密钥。 */
export const ENV_ADMIN_KEY = "ADMIN_SHARED_KEY";

/** 管理端密钥请求头名。 */
export const ADMIN_KEY_HEADER = "x-admin-key";

/** 默认每页扫描的批次数。 */
export const DEFAULT_BATCH_LIMIT = 5;

/** 每页批次数硬上限。 */
export const MAX_BATCH_LIMIT = 10;

/**
 * 累计读取字节预算（自设，非平台限制）。
 *
 * 计入本次查询读到的所有批次对象，包含一条都没匹配上的批次：这些字节同样
 * 被 SDK 缓冲进了函数内存。
 */
export const MAX_READ_BYTES = 16 * 1024 * 1024;

/**
 * 响应字节预算（自设）。官方 Cloud Functions 响应体上限 6 MB
 * (https://pages.edgeone.ai/document/limits-and-quotas)，这里取 5 MiB 留出
 * 余量。注意 6 MB 与 6 MiB 不同，不能混用。
 */
export const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
const HOUR_PATTERN = /^(\d{2})$/;

/**
 * @param {number} n
 * @param {number} width
 * @returns {string}
 */
function pad(n, width) {
  return String(n).padStart(width, "0");
}

/**
 * 当前 UTC 日期与小时，用作未指定时间窗口时的默认值。
 *
 * @param {Date} now
 * @returns {{ datePart: string, hourPart: string }}
 */
export function defaultUtcDateHour(now) {
  return {
    datePart: `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1, 2)}-${pad(
      now.getUTCDate(),
      2
    )}`,
    hourPart: pad(now.getUTCHours(), 2),
  };
}

/**
 * 校验是否为真实存在的日历日期（拒绝 2026-02-30 这类不存在的日期）。
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isValidCalendarDate(value) {
  const m = DATE_PATTERN.exec(value);
  if (m === null) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  const d = new Date(Date.UTC(year, month - 1, day));
  return (
    d.getUTCFullYear() === year &&
    d.getUTCMonth() === month - 1 &&
    d.getUTCDate() === day
  );
}

/**
 * 解析并校验有界整数参数。
 *
 * 返回 undefined 表示参数未提供；返回 'invalid' 表示提供了但非法（包含显式
 * 空串：那是调用方拼接错误，不能当作未提供）。
 *
 * @param {string|undefined} raw
 * @param {{ min: number, max: number }} range
 * @returns {number|undefined|'invalid'}
 */
export function parseBoundedInt(raw, range) {
  if (raw === undefined || raw === null) return undefined;
  const s = String(raw).trim();
  if (s.length === 0) return "invalid";
  if (!/^\d+$/.test(s)) return "invalid";
  const n = Number(s);
  if (!Number.isSafeInteger(n)) return "invalid";
  if (n < range.min || n > range.max) return "invalid";
  return n;
}

/**
 * 校验字符串类过滤参数：未提供返回 undefined，显式空值或超长返回 'invalid'。
 *
 * @param {string|undefined} raw
 * @param {number} maxLength
 * @returns {string|undefined|'invalid'}
 */
export function parseFilterString(raw, maxLength) {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "string") return "invalid";
  if (raw.length === 0) return "invalid";
  if (raw.length > maxLength) return "invalid";
  return raw;
}

/**
 * 判断单条记录是否命中过滤条件。
 *
 * 状态码同时比对边缘响应码与回源响应码：522 类故障的关键证据常在
 * OriginResponseStatusCode 上（docs/reference/61300.md），只看边缘码会漏。
 * 回源状态码 -1 表示本次未回源，不参与状态匹配。
 *
 * @param {Record<string, unknown>} record
 * @param {object} filters
 * @returns {boolean}
 */
export function recordMatchesFilters(record, filters) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return false;
  const { statusCode, statusMin, statusMax, requestHost, requestId } = filters;

  const candidates = [];
  for (const name of ["EdgeResponseStatusCode", "OriginResponseStatusCode"]) {
    const v = record[name];
    if (typeof v === "number" && Number.isInteger(v) && v >= 100 && v <= 599) {
      candidates.push(v);
    } else if (typeof v === "string" && /^\d{3}$/.test(v)) {
      candidates.push(Number(v));
    }
  }

  if (statusCode !== undefined && !candidates.includes(statusCode)) return false;
  if (statusMin !== undefined || statusMax !== undefined) {
    const lo = statusMin ?? 100;
    const hi = statusMax ?? 599;
    if (!candidates.some((v) => v >= lo && v <= hi)) return false;
  }
  if (requestHost !== undefined && record.RequestHost !== requestHost) return false;
  if (requestId !== undefined && record.RequestID !== requestId) return false;
  return true;
}

/**
 * 核心查询处理。与 HTTP 框架无关，可直接单测。
 *
 * @param {object} params
 * @returns {Promise<{ status: number, body: object, headers?: Record<string,string> }>}
 */
export async function handleAdminRequest({
  method = "GET",
  adminKeyHeader,
  env,
  store,
  date,
  hour,
  status,
  statusMin,
  statusMax,
  requestHost,
  requestId,
  limit,
  cursor,
  now,
  maxReadBytes = MAX_READ_BYTES,
  maxResponseBytes = MAX_RESPONSE_BYTES,
}) {
  // ─── 1. 方法 ──────────────────────────────────────────────────────
  if (method !== "GET") {
    return {
      status: 405,
      body: { error: "method_not_allowed" },
      headers: { allow: "GET" },
    };
  }

  // ─── 2. 鉴权（先于任何存储 I/O） ─────────────────────────────────
  const expected = env[ENV_ADMIN_KEY];
  if (typeof expected !== "string" || expected.length === 0) {
    return { status: 503, body: { error: "admin_key_not_configured" } };
  }
  if (!verifySharedSecret(adminKeyHeader, expected)) {
    return { status: 401, body: { error: "unauthorized" } };
  }

  // ─── 3. 时间窗口 ────────────────────────────────────────────────
  if ((date === undefined) !== (hour === undefined)) {
    return {
      status: 400,
      body: { error: "date_and_hour_must_be_given_together" },
    };
  }

  let datePart;
  let hourPart;
  let usedDefaultWindow = false;

  if (date === undefined) {
    const d = defaultUtcDateHour(now ?? new Date());
    datePart = d.datePart;
    hourPart = d.hourPart;
    usedDefaultWindow = true;
  } else {
    if (typeof date !== "string" || !isValidCalendarDate(date)) {
      return {
        status: 400,
        body: { error: "invalid_date", expected: "YYYY-MM-DD (UTC)" },
      };
    }
    const hm = typeof hour === "string" ? HOUR_PATTERN.exec(hour) : null;
    if (hm === null || Number(hm[1]) > 23) {
      return {
        status: 400,
        body: { error: "invalid_hour", expected: "00..23 (UTC)" },
      };
    }
    datePart = date;
    hourPart = hm[1];
  }

  // ─── 4. 过滤与分页参数 ──────────────────────────────────────────
  const statusValue = parseBoundedInt(status, { min: 100, max: 599 });
  if (statusValue === "invalid") {
    return { status: 400, body: { error: "invalid_status", expected: "100..599" } };
  }
  const statusMinValue = parseBoundedInt(statusMin, { min: 100, max: 599 });
  if (statusMinValue === "invalid") {
    return { status: 400, body: { error: "invalid_status_min", expected: "100..599" } };
  }
  const statusMaxValue = parseBoundedInt(statusMax, { min: 100, max: 599 });
  if (statusMaxValue === "invalid") {
    return { status: 400, body: { error: "invalid_status_max", expected: "100..599" } };
  }
  if (
    statusMinValue !== undefined &&
    statusMaxValue !== undefined &&
    statusMinValue > statusMaxValue
  ) {
    return { status: 400, body: { error: "status_range_inverted" } };
  }
  if (
    statusValue !== undefined &&
    (statusMinValue !== undefined || statusMaxValue !== undefined)
  ) {
    return { status: 400, body: { error: "status_and_range_are_mutually_exclusive" } };
  }

  const hostValue = parseFilterString(requestHost, 253);
  if (hostValue === "invalid") {
    return { status: 400, body: { error: "invalid_host" } };
  }
  const requestIdValue = parseFilterString(requestId, 128);
  if (requestIdValue === "invalid") {
    return { status: 400, body: { error: "invalid_request_id" } };
  }

  const limitValue = parseBoundedInt(limit, { min: 1, max: MAX_BATCH_LIMIT });
  if (limitValue === "invalid") {
    return {
      status: 400,
      body: { error: "invalid_limit", expected: `1..${MAX_BATCH_LIMIT}` },
    };
  }
  const effectiveLimit = limitValue ?? DEFAULT_BATCH_LIMIT;

  const cursorValue = parseFilterString(cursor, 4096);
  if (cursorValue === "invalid") {
    return { status: 400, body: { error: "invalid_cursor" } };
  }

  // ─── 5. 列举（严格限定单分区前缀） ──────────────────────────────
  const prefix = `logs/${datePart}/${hourPart}/`;
  let listResult;
  try {
    listResult = await listBatches({
      store,
      prefix,
      limit: effectiveLimit,
      ...(cursorValue !== undefined ? { cursor: cursorValue } : {}),
    });
  } catch {
    // 列举失败必须显式报错：返回空结果会被误读为「该小时没有日志」。
    return { status: 500, body: { error: "storage_list_failed" } };
  }

  if (!listResult || !Array.isArray(listResult.blobs)) {
    return { status: 500, body: { error: "storage_list_invalid" } };
  }
  const blobs = listResult.blobs;

  // ─── 6. 逐批读取（读失败即失败，不跳过） ────────────────────────
  const filters = {
    statusCode: statusValue,
    statusMin: statusMinValue,
    statusMax: statusMaxValue,
    requestHost: hostValue,
    requestId: requestIdValue,
  };

  const batches = [];
  let matchedRecords = 0;
  let scannedRecords = 0;
  let readBytes = 0;
  let responseBytes = 0;

  for (const blob of blobs) {
    if (!blob || typeof blob.key !== "string" || blob.key.length === 0) {
      return { status: 500, body: { error: "storage_list_invalid" } };
    }

    let payload;
    try {
      payload = await getBatch({ store, key: blob.key });
    } catch {
      return { status: 500, body: { error: "storage_read_failed", key: blob.key } };
    }
    if (payload === null) {
      // 列举里有键但读不到内容：存储状态不一致，显式报错。
      return { status: 500, body: { error: "batch_missing_after_list", key: blob.key } };
    }
    if (
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      !Array.isArray(payload.records)
    ) {
      return { status: 500, body: { error: "batch_schema_invalid", key: blob.key } };
    }
    if (payload.schemaVersion !== BATCH_SCHEMA_VERSION) {
      // schema 版本不符不能当作零匹配，否则查询会静默漏掉这些批次。
      return {
        status: 500,
        body: {
          error: "batch_schema_version_unsupported",
          key: blob.key,
          expected: BATCH_SCHEMA_VERSION,
        },
      };
    }

    // 读取预算：不匹配的记录同样已被读入内存，必须计入。
    readBytes += Buffer.byteLength(JSON.stringify(payload), "utf8");
    scannedRecords += payload.records.length;
    if (readBytes > maxReadBytes) {
      return {
        status: 413,
        body: {
          error: "read_budget_exceeded",
          maxBytes: maxReadBytes,
          hint: "reduce limit so fewer batches are read per request",
        },
      };
    }

    const matched = payload.records.filter((r) => recordMatchesFilters(r, filters));
    if (matched.length === 0) continue;

    const entry = {
      key: blob.key,
      batchId: typeof payload.batchId === "string" ? payload.batchId : null,
      partitionTimestampMs:
        typeof payload.partitionTimestampMs === "number"
          ? payload.partitionTimestampMs
          : null,
      contentDigest:
        typeof payload.contentDigest === "string" ? payload.contentDigest : null,
      matchedRecords: matched.length,
      records: matched,
    };

    const entryBytes = Buffer.byteLength(JSON.stringify(entry), "utf8");
    if (responseBytes + entryBytes > maxResponseBytes) {
      // 不返回部分结果 + cursor：那等于静默丢数据。要求调用方缩小范围。
      return {
        status: 413,
        body: {
          error: "response_budget_exceeded",
          maxBytes: maxResponseBytes,
          hint: "reduce limit, or narrow the filters (status/host/requestId)",
        },
      };
    }
    responseBytes += entryBytes;
    matchedRecords += matched.length;
    batches.push(entry);
  }

  return {
    status: 200,
    body: {
      datePart,
      hourPart,
      usedDefaultWindow,
      boundedPage: true,
      scannedPartitions: 1,
      scannedBatches: blobs.length,
      scannedRecords,
      batchLimit: effectiveLimit,
      matchedRecords,
      readBytes,
      responseBytes,
      batches,
      ...(listResult.cursor !== undefined ? { cursor: listResult.cursor } : {}),
      note: "counts describe this bounded page only, not the whole partition",
    },
  };
}
