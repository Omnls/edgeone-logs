/**
 * server/storage/batch-store.js
 *
 * 批次对象的存储层。只负责「把一批已脱敏的记录幂等地写进 Pages Blob」，
 * 不做鉴权、解析、脱敏，也不认识 HTTP。
 *
 * ─── 内容身份与幂等 ───────────────────────────────────────────────────
 *
 * 键完全由「分区时间 + 内容派生的 batchId」决定，写入一律用条件写
 * (onlyIfNew:true)。条件写冲突只说明键已存在，不等于内容相同，因此这里会
 * 强一致读回已存对象，逐项核对 schemaVersion、记录条数和记录内容摘要：
 * 完全一致才判定为 duplicate 并允许调用方 ACK，其余情况（读不到、读失败、
 * schema 不符、摘要不符）一律抛 BatchConflictError，绝不谎报已接收。
 *
 * 规范化只用于「内容身份」的计算与存储：对象键递归按字典序重排，整批记录按
 * 各自规范字符串排序。数组顺序保留（日志里数组顺序有语义），完全重复的记录
 * 也全部保留（周期性日志会产生内容相同的多条记录，去重就是丢数据）。
 * meta 不参与身份比较——它带运行期信息，参与比较会让重投永远对不上。
 */

import { createHash } from "node:crypto";

/** 单批次序列化字节上限（自设）。SDK 读取单对象时会先整体缓冲，故留足余量。 */
export const DEFAULT_MAX_BATCH_BYTES = 4 * 1024 * 1024;

/** 单批次记录条数上限（自设）。 */
export const DEFAULT_MAX_BATCH_RECORDS = 5000;

/** 列举默认页大小。 */
export const DEFAULT_LIST_LIMIT = 1000;

/**
 * Blob 键长度上限：600 字节。
 *
 * 这是 SDK 实际强制的值（node_modules/@edgeone/pages-blob/dist/index.js 中的
 * 键校验函数：超过 600 字节抛 InvalidKeyError），不是本模块的自设假设。
 */
export const MAX_KEY_BYTES = 600;

/** 存储对象的 schema 版本。读回校验时必须精确匹配。 */
export const BATCH_SCHEMA_VERSION = 1;

/** SDK 条件写冲突的错误码。 */
const PRECONDITION_FAILED = "PRECONDITION_FAILED";

/** batchId 允许的形状：短、URL 安全，绝不含原始 URL 或凭据。 */
const BATCH_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

/** 记录条数超限。 */
export class BatchTooManyRecordsError extends Error {
  /**
   * @param {number} count
   * @param {number} max
   */
  constructor(count, max) {
    super(`batch has ${count} records, exceeding the limit of ${max}`);
    this.name = "BatchTooManyRecordsError";
    this.code = "BATCH_TOO_MANY_RECORDS";
    this.count = count;
    this.max = max;
  }
}

/** 序列化字节超限。 */
export class BatchTooLargeError extends Error {
  /**
   * @param {number} bytes
   * @param {number} max
   */
  constructor(bytes, max) {
    super(`batch serializes to ${bytes} bytes, exceeding the limit of ${max}`);
    this.name = "BatchTooLargeError";
    this.code = "BATCH_TOO_LARGE";
    this.bytes = bytes;
    this.max = max;
  }
}

/**
 * 键已存在，但已存对象与本次要写的内容不一致（或无法确认一致）。
 *
 * 这不是「重复投递」，调用方不得 ACK。
 */
export class BatchConflictError extends Error {
  /**
   * @param {string} detail
   * @param {string} key
   */
  constructor(detail, key) {
    super(`existing batch object conflicts: ${detail}`);
    this.name = "BatchConflictError";
    this.code = "BATCH_CONFLICT";
    this.detail = detail;
    this.key = key;
  }
}

/**
 * @param {number} n
 * @returns {string}
 */
function pad2(n) {
  return String(n).padStart(2, "0");
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 规范化序列化：对象键递归按字典序排列，数组顺序原样保留。
 *
 * 手写而不是 JSON.stringify(排序后的对象)：JS 对象对「整数样」键有自己的遍历
 * 顺序，靠插入顺序无法保证稳定输出。这里的结果只取决于内容本身。
 *
 * @param {unknown} value
 * @returns {string}
 */
function canonicalString(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "number") {
    return Number.isFinite(value) ? JSON.stringify(value) : "null";
  }
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (t === "bigint") return JSON.stringify(String(value));
  if (t === "undefined" || t === "function" || t === "symbol") return "null";
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalString(v)).join(",") + "]";
  }
  const keys = Object.keys(/** @type {object} */ (value)).sort();
  const parts = keys.map(
    (k) => JSON.stringify(k) + ":" + canonicalString(/** @type {any} */ (value)[k])
  );
  return "{" + parts.join(",") + "}";
}

/**
 * 递归重建取值：对象键按字典序重建，数组顺序保留。
 *
 * @param {unknown} value
 * @returns {unknown}
 */
function canonicalizeValue(value) {
  if (Array.isArray(value)) return value.map((v) => canonicalizeValue(v));
  if (!isPlainObject(value)) return value;
  /** @type {Record<string, unknown>} */
  const out = {};
  for (const k of Object.keys(/** @type {object} */ (value)).sort()) {
    // 不能用 out[k] = ...：k 为 "__proto__" 时这是对 out 原型的内建 setter，
    // 而不是创建自有属性，字段会静默消失。defineProperty 总是创建自有属性。
    Object.defineProperty(out, k, {
      value: canonicalizeValue(/** @type {any} */ (value)[k]),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * 规范化一批记录：每条递归排序键，再按各自规范字符串排序整批。
 *
 * 重复记录全部保留；嵌套数组顺序保留。
 *
 * @param {unknown[]} records
 * @returns {unknown[]}
 */
export function canonicalizeRecords(records) {
  if (!Array.isArray(records)) {
    throw new TypeError("records must be an array");
  }
  const wrapped = records.map((r) => {
    const canonical = canonicalizeValue(r);
    return { canonical, text: canonicalString(canonical) };
  });
  wrapped.sort((a, b) => (a.text < b.text ? -1 : a.text > b.text ? 1 : 0));
  return wrapped.map((w) => w.canonical);
}

/**
 * 一批记录的内容摘要：完整 64 位十六进制 SHA-256。
 *
 * 与记录顺序、对象键顺序无关；内容有任何差异必然得到不同摘要。
 *
 * @param {unknown[]} records
 * @returns {string}
 */
export function computeRecordsDigest(records) {
  const canonical = canonicalizeRecords(records);
  const material =
    "[" + canonical.map((r) => canonicalString(r)).join(",") + "]";
  return createHash("sha256").update(material, "utf8").digest("hex");
}

/**
 * 由批次自身的时间戳计算 UTC 分区路径片段。
 *
 * @param {number} partitionTimestampMs
 * @returns {{ datePart: string, hourPart: string }}
 */
export function computePartition(partitionTimestampMs) {
  if (
    typeof partitionTimestampMs !== "number" ||
    !Number.isFinite(partitionTimestampMs)
  ) {
    throw new TypeError("partitionTimestampMs must be a finite number");
  }
  const d = new Date(partitionTimestampMs);
  if (Number.isNaN(d.getTime())) {
    throw new TypeError("partitionTimestampMs is not a valid timestamp");
  }
  return {
    datePart: `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(
      d.getUTCDate()
    )}`,
    hourPart: pad2(d.getUTCHours()),
  };
}

/**
 * 计算批次键：logs/<UTC 日期>/<UTC 小时>/<batchId>.json
 *
 * @param {object} params
 * @param {string} params.batchId
 * @param {number} params.partitionTimestampMs
 * @returns {string}
 */
export function computeBatchKey({ batchId, partitionTimestampMs }) {
  if (typeof batchId !== "string" || !BATCH_ID_PATTERN.test(batchId)) {
    throw new TypeError(
      "batchId must match /^[A-Za-z0-9_-]{1,128}$/ (no URLs, query strings or raw credentials)"
    );
  }
  const { datePart, hourPart } = computePartition(partitionTimestampMs);
  const key = `logs/${datePart}/${hourPart}/${batchId}.json`;
  const bytes = Buffer.byteLength(key, "utf8");
  if (bytes > MAX_KEY_BYTES) {
    throw new RangeError(
      `blob key is ${bytes} bytes, exceeding the SDK limit of ${MAX_KEY_BYTES}`
    );
  }
  return key;
}

/**
 * 计算好一次写入所需的一切，但不做任何 I/O。
 *
 * 调用方可以先对整批的每个分区、每个分块调用本函数完成全部校验，确认全部合法
 * 后再开始写，从而避免「前几组已写入、后一组才发现非法」。
 *
 * @param {object} params
 * @param {string} params.batchId
 * @param {number} params.partitionTimestampMs 事件时间，不是接收时间。
 * @param {unknown[]} params.records 已脱敏记录。
 * @param {number} [params.maxBatchBytes]
 * @param {number} [params.maxBatchRecords]
 * @param {Record<string, unknown>} [params.meta] 不参与内容身份比较。
 * @returns {{ key: string, payload: Record<string, unknown>, bytes: number, recordCount: number, contentDigest: string }}
 */
export function prepareBatch({
  batchId,
  partitionTimestampMs,
  records,
  maxBatchBytes = DEFAULT_MAX_BATCH_BYTES,
  maxBatchRecords = DEFAULT_MAX_BATCH_RECORDS,
  meta,
}) {
  if (!Array.isArray(records)) {
    throw new TypeError("records must be an array");
  }
  if (records.length === 0) {
    throw new TypeError("records must contain at least one record");
  }

  // 键先算：batchId 或时间戳非法时立刻失败。
  const key = computeBatchKey({ batchId, partitionTimestampMs });

  if (records.length > maxBatchRecords) {
    throw new BatchTooManyRecordsError(records.length, maxBatchRecords);
  }

  const canonical = canonicalizeRecords(records);
  const contentDigest = computeRecordsDigest(canonical);

  const payload = {
    schemaVersion: BATCH_SCHEMA_VERSION,
    batchId,
    partitionTimestampMs,
    recordCount: canonical.length,
    contentDigest,
    ...(meta !== undefined ? { meta } : {}),
    records: canonical,
  };

  // 按真正要写出的完整对象计量，而不是只算 records 部分。
  const bytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
  if (bytes > maxBatchBytes) {
    throw new BatchTooLargeError(bytes, maxBatchBytes);
  }

  return { key, payload, bytes, recordCount: canonical.length, contentDigest };
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isPreconditionFailed(err) {
  return (
    typeof err === "object" &&
    err !== null &&
    /** @type {{ code?: unknown }} */ (err).code === PRECONDITION_FAILED
  );
}

/**
 * 读回已存对象，核对是否与本次内容完全一致。一致则正常返回，否则抛
 * BatchConflictError。
 *
 * @param {object} params
 * @param {{ get: Function }} params.store
 * @param {string} params.key
 * @param {string} params.contentDigest
 * @param {number} params.recordCount
 * @returns {Promise<void>}
 */
async function assertExistingMatches({ store, key, contentDigest, recordCount }) {
  let existing;
  try {
    // 强一致读取：条件写刚刚失败，必须绕过 CDN 缓存域名读到最新对象。
    existing = await store.get(key, { type: "json", consistency: "strong" });
  } catch (err) {
    const code =
      typeof err === "object" && err !== null && typeof (/** @type {any} */ (err).code) === "string"
        ? /** @type {any} */ (err).code
        : "read_failed";
    // 读不出来就无法断定内容一致，不能 ACK。
    throw new BatchConflictError(`existing object read failed (${code})`, key);
  }

  if (existing === null || existing === undefined) {
    throw new BatchConflictError("conditional write failed but object is absent", key);
  }
  if (!isPlainObject(existing)) {
    throw new BatchConflictError("existing object is not a JSON object", key);
  }
  const obj = /** @type {Record<string, unknown>} */ (existing);
  if (obj.schemaVersion !== BATCH_SCHEMA_VERSION) {
    throw new BatchConflictError(
      `schemaVersion mismatch (expected ${BATCH_SCHEMA_VERSION})`,
      key
    );
  }
  if (!Array.isArray(obj.records)) {
    throw new BatchConflictError("existing object has no records array", key);
  }
  if (obj.recordCount !== recordCount || obj.records.length !== recordCount) {
    throw new BatchConflictError("recordCount mismatch", key);
  }
  // 重新计算摘要，不信任对象里自带的 contentDigest 字段。
  if (computeRecordsDigest(obj.records) !== contentDigest) {
    throw new BatchConflictError("content digest mismatch", key);
  }
}

/**
 * 幂等写入一个批次。
 *
 * - 首次写入成功 -> status:'written'
 * - 条件写冲突且读回内容完全一致 -> status:'duplicate'（可以 ACK）
 * - 其余任何情况一律抛错，调用方不得视为已接收。
 *
 * @param {object} params
 * @param {{ setJSON: Function, get?: Function }} params.store
 * @param {string} params.batchId
 * @param {number} params.partitionTimestampMs
 * @param {unknown[]} params.records
 * @param {number} [params.maxBatchBytes]
 * @param {number} [params.maxBatchRecords]
 * @param {Record<string, unknown>} [params.meta]
 * @param {{ key: string, payload: Record<string, unknown>, bytes: number, recordCount: number, contentDigest: string }} [params.prepared]
 *   已由 prepareBatch 算好的结果，避免重复计算与重复校验。
 * @returns {Promise<{ status: 'written'|'duplicate', key: string, recordCount: number, bytes: number, contentDigest: string }>}
 */
export async function storeBatch({
  store,
  batchId,
  partitionTimestampMs,
  records,
  maxBatchBytes = DEFAULT_MAX_BATCH_BYTES,
  maxBatchRecords = DEFAULT_MAX_BATCH_RECORDS,
  meta,
  prepared,
}) {
  if (!store || typeof store.setJSON !== "function") {
    throw new TypeError("store must provide setJSON()");
  }

  const plan =
    prepared ??
    prepareBatch({
      batchId,
      partitionTimestampMs,
      records,
      maxBatchBytes,
      maxBatchRecords,
      meta,
    });

  try {
    await store.setJSON(plan.key, plan.payload, { onlyIfNew: true });
  } catch (err) {
    if (isPreconditionFailed(err)) {
      if (typeof store.get !== "function") {
        throw new BatchConflictError(
          "store cannot read back, duplicate cannot be verified",
          plan.key
        );
      }
      await assertExistingMatches({
        store,
        key: plan.key,
        contentDigest: plan.contentDigest,
        recordCount: plan.recordCount,
      });
      return {
        status: "duplicate",
        key: plan.key,
        recordCount: plan.recordCount,
        bytes: plan.bytes,
        contentDigest: plan.contentDigest,
      };
    }
    throw err;
  }

  return {
    status: "written",
    key: plan.key,
    recordCount: plan.recordCount,
    bytes: plan.bytes,
    contentDigest: plan.contentDigest,
  };
}

/**
 * 读取单个批次。键不存在返回 null；存储出错则抛出，由调用方映射为 5xx——
 * 「读不到」绝不能被当成「没有匹配」。
 *
 * @param {object} params
 * @param {{ get: Function }} params.store
 * @param {string} params.key
 * @returns {Promise<unknown|null>}
 */
export async function getBatch({ store, key }) {
  if (!store || typeof store.get !== "function") {
    throw new TypeError("store must provide get()");
  }
  if (typeof key !== "string" || key.length === 0) {
    throw new TypeError("key must be a non-empty string");
  }
  const value = await store.get(key, { type: "json", consistency: "strong" });
  return value === undefined ? null : value;
}

/**
 * 有界列举批次键。
 *
 * 强制 paginate:false，让 SDK 只取一页并返回 cursor；默认的 paginate:true 会在
 * 分区很大时把所有页拉完，可能耗尽函数时长与内存。directories:false 确保返回
 * 对象键而不是公共前缀。cursor 原样透传、原样返回，不做改写。
 *
 * @param {object} params
 * @param {{ list: Function }} params.store
 * @param {string} params.prefix
 * @param {number} [params.limit]
 * @param {string} [params.cursor]
 * @returns {Promise<{ blobs: { key: string, etag: string }[], cursor?: string }>}
 */
export async function listBatches({ store, prefix, limit, cursor }) {
  if (!store || typeof store.list !== "function") {
    throw new TypeError("store must provide list()");
  }
  if (typeof prefix !== "string" || prefix.length === 0) {
    throw new TypeError("prefix must be a non-empty string");
  }
  let effectiveLimit = DEFAULT_LIST_LIMIT;
  if (limit !== undefined) {
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new TypeError("limit must be a positive integer");
    }
    effectiveLimit = limit;
  }
  if (cursor !== undefined && typeof cursor !== "string") {
    throw new TypeError("cursor must be a string when provided");
  }

  const result = await store.list({
    prefix,
    limit: effectiveLimit,
    directories: false,
    paginate: false,
    consistency: "strong",
    ...(cursor !== undefined ? { cursor } : {}),
  });

  const blobs = Array.isArray(result?.blobs) ? result.blobs : [];
  return {
    blobs,
    ...(typeof result?.cursor === "string" && result.cursor.length > 0
      ? { cursor: result.cursor }
      : {}),
  };
}
