/**
 * server/routes/ingest.js
 *
 * 日志接收端点的核心逻辑。真实 Pages 入口在 cloud-functions/edgeone-logs.js，
 * 本文件只导出与 HTTP 框架无关的纯函数，便于离线单测。
 *
 * ─── 处理顺序 ─────────────────────────────────────────────────────────
 *
 *   1. 方法（非 POST -> 405 + Allow）
 *   2. Content-Encoding（未知或叠加编码 -> 415）
 *   3. 密钥配置（缺失或两种密钥相同 -> 503）
 *   4. 独立 INGEST_SHARED_KEY（不匹配 -> 401）
 *   5. EdgeOne 官方签名（是否强制由部署配置决定）
 *   6. 原始正文体积（-> 413）
 *   7. 解压 + 解析（有界；任一记录非法 -> 整批 400，零写入）
 *   8. 脱敏
 *   9. 按记录自身 UTC 小时分组、切块，并完成全部上限校验
 *  10. 全部校验通过后才开始写入
 *
 * 前五步都不需要读取请求正文，因此入口可以先鉴权再决定是否消耗带宽。
 *
 * ─── 写入原子性的真实边界 ─────────────────────────────────────────────
 *
 * 第 9 步用 prepareBatch 对每个批次做完整校验（键、记录数、规范化、完整对象
 * 字节数），任何一个批次不合格就整批 400 且零写入。但一旦进入第 10 步，
 * Blob 侧的失败可能留下已写入的前若干个对象，此时返回 5xx 让 EdgeOne 重投；
 * 因为键完全由内容派生，重投会命中已写对象并被判定为 duplicate，不会重复
 * 存储。这是「先全量校验、再逐个写入」的真实语义，不是跨对象事务。
 *
 * ─── 签名层的启用判定 ─────────────────────────────────────────────────
 *
 * 是否强制签名由「环境变量是否配置」决定，而不是「请求里有没有签名」：
 *   - SecretId 与 SecretKey 都已配置 -> 每个投递都必须带合法签名。缺参数
 *     不能降级放行，否则攻击者只要去掉 query 参数就绕过了一层校验。
 *   - 只配置了其中一个，或 SecretKey 长度不是官方要求的 32 位 -> 配置不
 *     完整，返回 503，不猜测意图。
 *   - 两个都没配置 -> 签名层未启用，仅由独立 header 鉴权把关；此时若请求
 *     仍带签名参数，无法验证，按 401 拒绝而不是忽略。
 */

import { verifyEdgeOneSignature, verifySharedSecret } from "../lib/auth.js";
import { LOG_BODY_ERROR_CODES, parseLogBody } from "../lib/parse-log-body.js";
import { redactRecords } from "../lib/redact.js";
import {
  DEFAULT_MAX_BATCH_BYTES,
  DEFAULT_MAX_BATCH_RECORDS,
  canonicalizeRecords,
  computeRecordsDigest,
  prepareBatch,
  storeBatch,
} from "../storage/batch-store.js";

/**
 * 原始（可能是 gzip 压缩后的）请求正文上限。
 *
 * 官方 Cloud Functions 的请求体上限是 6 MB
 * (https://pages.edgeone.ai/document/limits-and-quotas)。注意 6 MB 与 6 MiB
 * 不是同一个数：这里取 4 MiB，明确低于官方上限，留出余量，属本项目自设值。
 */
export const DEFAULT_MAX_INGEST_BODY_BYTES = 4 * 1024 * 1024;

/** 单次投递允许跨越的 UTC 小时分区数上限（自设）。 */
export const DEFAULT_MAX_PARTITIONS = 24;

/** 单次投递允许生成的批次对象数上限（自设）。 */
export const DEFAULT_MAX_CHUNKS = 32;

/** 环境变量名，详见 README.md 与 docs/operations.md。 */
export const ENV_EDGEONE_SECRET_ID = "EDGEONE_LOG_SECRET_ID";
export const ENV_EDGEONE_SECRET_KEY = "EDGEONE_LOG_SECRET_KEY";
export const ENV_INGEST_KEY = "INGEST_SHARED_KEY";
export const ENV_ADMIN_KEY = "ADMIN_SHARED_KEY";

/** 独立接收密钥的请求头名。官方支持自定义请求头（61296.md:34）。 */
export const INGEST_KEY_HEADER = "x-ingest-key";

/** 官方要求 SecretKey 固定 32 位（61296.md:151）。 */
export const EDGEONE_SECRET_KEY_LENGTH = 32;

/** 生产环境建议的独立密钥最小长度。不足只在响应里给出提示，不改变判定。 */
export const RECOMMENDED_KEY_MIN_LENGTH = 24;

/** 视为「未压缩」的 Content-Encoding 取值。 */
const IDENTITY_ENCODINGS = new Set(["", "identity"]);

/**
 * 判定 Content-Encoding。
 *
 * 只接受空/identity 与单一 gzip。未知编码（br、deflate、zstd 等）或叠加编码
 * （如 gzip, gzip）一律 unsupported：本模块只实现一层 gzip 解压，猜测其余情况
 * 会把压缩字节当 JSON 解析，给出误导性的 400。
 *
 * @param {string|undefined} raw Content-Encoding 请求头原值。
 * @returns {{ kind: 'identity'|'gzip'|'unsupported' }}
 */
export function classifyContentEncoding(raw) {
  const value = (typeof raw === "string" ? raw : "").trim().toLowerCase();
  if (IDENTITY_ENCODINGS.has(value)) return { kind: "identity" };

  const parts = value
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  if (parts.length !== 1) return { kind: "unsupported" };
  if (parts[0] === "gzip") return { kind: "gzip" };
  if (IDENTITY_ENCODINGS.has(parts[0])) return { kind: "identity" };
  return { kind: "unsupported" };
}

/** 合理的时间戳年份范围，用于排除明显异常的数字取值。 */
const MIN_TIMESTAMP_MS = Date.UTC(2000, 0, 1);
const MAX_TIMESTAMP_MS = Date.UTC(2100, 0, 1);

/** ISO8601：日期 + 时间 + 必须存在的时区偏移。 */
const ISO_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})$/;

/**
 * 严格解析记录时间字段为 epoch 毫秒。
 *
 * 官方预设字段 RequestTime / LogTime / EdgeEndTime 均为 Timestamp ISO8601
 * （docs/reference/61300.md:24,26,60，示例 2024-10-14T05:13:43Z）。
 *
 * 严格性要求：
 *  - 只接受明确的 10 位秒级或 13 位毫秒级纯数字，不做「小于某个数就是秒」的
 *    模糊猜测，并且结果必须落在合理年份范围内。
 *  - ISO8601 必须带明确时区（Z 或 ±HH:MM / ±HHMM）。无时区的本地时间会随运行
 *    时区落到不同小时分区，破坏分区稳定性，因此拒绝。
 *  - 日历日期必须真实存在。Date.parse 会把 2024-02-30 静默滚动成 3 月 1 日，
 *    这里逐字段回读校验，发生滚动即视为非法。
 *
 * @param {unknown} raw
 * @returns {number|null} epoch 毫秒；无法确定时返回 null，绝不回退到当前时间。
 */
export function parseRecordTimestampMs(raw) {
  if (typeof raw === "number") {
    if (!Number.isFinite(raw) || !Number.isInteger(raw)) return null;
    const ms = String(Math.abs(raw)).length >= 13 ? raw : raw * 1000;
    return ms >= MIN_TIMESTAMP_MS && ms < MAX_TIMESTAMP_MS ? ms : null;
  }
  if (typeof raw !== "string") return null;

  const s = raw.trim();
  if (s.length === 0 || s === "-") return null;

  if (/^\d{13}$/.test(s)) {
    const ms = Number(s);
    return ms >= MIN_TIMESTAMP_MS && ms < MAX_TIMESTAMP_MS ? ms : null;
  }
  if (/^\d{10}$/.test(s)) {
    const ms = Number(s) * 1000;
    return ms >= MIN_TIMESTAMP_MS && ms < MAX_TIMESTAMP_MS ? ms : null;
  }

  const m = ISO_PATTERN.exec(s);
  if (m === null) return null;

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  // 逐字段回读，拒绝 Date 的自动滚动（例如 2024-02-30 -> 2024-03-01）。
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (
    probe.getUTCFullYear() !== year ||
    probe.getUTCMonth() !== month - 1 ||
    probe.getUTCDate() !== day
  ) {
    return null;
  }

  const fraction = m[7] === undefined ? 0 : Number(`0.${m[7]}`) * 1000;
  let ms = Date.UTC(year, month - 1, day, hour, minute, second) + Math.floor(fraction);

  const zone = m[8];
  if (zone !== "Z") {
    const sign = zone[0] === "-" ? -1 : 1;
    const digits = zone.slice(1).replace(":", "");
    const offsetHours = Number(digits.slice(0, 2));
    const offsetMinutes = Number(digits.slice(2, 4));
    if (offsetHours > 23 || offsetMinutes > 59) return null;
    ms -= sign * (offsetHours * 60 + offsetMinutes) * 60 * 1000;
  }

  if (!Number.isFinite(ms)) return null;
  return ms >= MIN_TIMESTAMP_MS && ms < MAX_TIMESTAMP_MS ? ms : null;
}

/** 依次尝试的时间字段名，优先使用请求到达时间。 */
const TIME_FIELD_NAMES = ["RequestTime", "LogTime", "EdgeEndTime"];

/**
 * 取单条记录的分区时间。
 *
 * @param {Record<string, unknown>} record
 * @returns {number|null}
 */
export function recordTimestampMs(record) {
  if (!record || typeof record !== "object") return null;
  for (const name of TIME_FIELD_NAMES) {
    const ms = parseRecordTimestampMs(record[name]);
    if (ms !== null) return ms;
  }
  return null;
}

/**
 * UTC 小时桶键，形如 2024-10-14T05。
 *
 * @param {number} ms
 * @returns {string}
 */
function hourBucketKey(ms) {
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(
    d.getUTCHours()
  )}`;
}

/**
 * 按记录自身的 UTC 小时分组。
 *
 * 跨小时的一次投递会被拆到各自的小时分区，而不是整批塞进最早那个小时——否则
 * 按后续记录的实际小时去查会漏掉它们。每组的分区时间取组内最早的记录时间，
 * 只依赖内容，因此重投得到完全相同的键。
 *
 * @param {Record<string, unknown>[]} records
 * @returns {{ groups: { bucket: string, partitionTimestampMs: number, records: Record<string, unknown>[] }[], missing: number }}
 */
export function groupRecordsByUtcHour(records) {
  /** @type {Map<string, { bucket: string, partitionTimestampMs: number, records: Record<string, unknown>[] }>} */
  const map = new Map();
  let missing = 0;

  for (const record of records) {
    const ms = recordTimestampMs(record);
    if (ms === null) {
      missing += 1;
      continue;
    }
    const bucket = hourBucketKey(ms);
    const existing = map.get(bucket);
    if (existing === undefined) {
      map.set(bucket, { bucket, partitionTimestampMs: ms, records: [record] });
    } else {
      existing.records.push(record);
      if (ms < existing.partitionTimestampMs) existing.partitionTimestampMs = ms;
    }
  }

  const groups = Array.from(map.values()).sort((a, b) =>
    a.bucket < b.bucket ? -1 : a.bucket > b.bucket ? 1 : 0
  );
  return { groups, missing };
}

/**
 * 把一组记录按序列化字节与条数上限切成稳定的子批次。
 *
 * 调用方应先用 canonicalizeRecords 规范化并排序，这样切分结果只取决于内容，
 * 与投递顺序和对象键顺序无关，重投会得到完全相同的分块与键。
 *
 * 单条记录本身就超限时返回 oversizeIndex，由调用方明确报错，绝不截断或丢弃。
 *
 * @param {Record<string, unknown>[]} records
 * @param {number} maxBytes 单批次记录部分的字节上限（已扣除信封余量）。
 * @param {number} maxRecords 单批次条数上限。
 * @returns {{ chunks: Record<string, unknown>[][], oversizeIndex: number|null }}
 */
export function chunkRecords(records, maxBytes, maxRecords) {
  /** @type {Record<string, unknown>[][]} */
  const chunks = [];
  /** @type {Record<string, unknown>[]} */
  let current = [];
  let currentBytes = 0;

  for (let i = 0; i < records.length; i += 1) {
    const size = Buffer.byteLength(JSON.stringify(records[i]) ?? "null", "utf8");
    if (size > maxBytes) return { chunks, oversizeIndex: i };

    const wouldBytes = currentBytes + size + 1; // +1 计入分隔符
    if (current.length > 0 && (wouldBytes > maxBytes || current.length >= maxRecords)) {
      chunks.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(records[i]);
    currentBytes += size + 1;
  }
  if (current.length > 0) chunks.push(current);
  return { chunks, oversizeIndex: null };
}

/**
 * 由内容派生稳定的 batchId：完整记录内容的 SHA-256（64 位十六进制）。
 *
 * 不用 RequestID 集合：官方说明 WebSocket 等长连接会对同一 RequestID 周期性
 * 输出多条日志（docs/reference/61300.md），用 RequestID 作身份会把内容不同的
 * 两批日志判成同一批次而丢弃后者。内容摘要则保证内容不同必然键不同。
 *
 * @param {Record<string, unknown>[]} records
 * @returns {string}
 */
export function deriveBatchId(records) {
  return computeRecordsDigest(records);
}

/**
 * 读取并校验签名相关配置。
 *
 * @param {Record<string, string|undefined>} env
 * @returns {{ mode: 'enforced'|'disabled'|'misconfigured', secretId?: string, secretKey?: string, detail?: string }}
 */
export function resolveSignatureConfig(env) {
  const rawId = env[ENV_EDGEONE_SECRET_ID];
  const rawKey = env[ENV_EDGEONE_SECRET_KEY];
  const secretId = typeof rawId === "string" ? rawId.trim() : "";
  const secretKey = typeof rawKey === "string" ? rawKey.trim() : "";

  if (secretId.length === 0 && secretKey.length === 0) return { mode: "disabled" };
  if (secretId.length === 0 || secretKey.length === 0) {
    return { mode: "misconfigured", detail: "only one of SecretId/SecretKey is set" };
  }
  if (secretKey.length !== EDGEONE_SECRET_KEY_LENGTH) {
    return {
      mode: "misconfigured",
      detail: `SecretKey must be exactly ${EDGEONE_SECRET_KEY_LENGTH} characters`,
    };
  }
  return { mode: "enforced", secretId, secretKey };
}

/**
 * 从 query 中取出恰好一个取值；重复出现视为非法（签名参数不允许歧义）。
 *
 * @param {URLSearchParams} queryParams
 * @param {string} name
 * @returns {{ ok: true, value: string|undefined } | { ok: false }}
 */
function singleQueryValue(queryParams, name) {
  const all = queryParams.getAll(name);
  if (all.length === 0) return { ok: true, value: undefined };
  if (all.length > 1) return { ok: false };
  return { ok: true, value: all[0] };
}

/**
 * 方法、编码、配置与鉴权检查。全部不需要请求正文，入口可以先调用它再决定
 * 是否读取正文。
 *
 * @param {object} params
 * @param {string} params.method
 * @param {string|undefined} params.contentEncoding
 * @param {string} params.requestPath 请求路径（不含 query），用于签名计算。
 * @param {URLSearchParams} params.queryParams
 * @param {string|undefined} params.ingestKeyHeader
 * @param {Record<string, string|undefined>} params.env
 * @param {number} [params.nowSeconds] 仅测试用，覆盖签名过期判定的当前时间。
 * @returns {{ ok: true, gzip: boolean } | { ok: false, status: number, body: object, headers?: Record<string,string> }}
 */
export function authorizeIngest({
  method,
  contentEncoding,
  requestPath,
  queryParams,
  ingestKeyHeader,
  env,
  nowSeconds,
}) {
  // ─── 1. 方法 ───────────────────────────────────────────────────────
  if (method !== "POST") {
    return {
      ok: false,
      status: 405,
      body: { error: "method_not_allowed" },
      headers: { allow: "POST" },
    };
  }

  // ─── 2. Content-Encoding ──────────────────────────────────────────
  const encoding = classifyContentEncoding(contentEncoding);
  if (encoding.kind === "unsupported") {
    return {
      ok: false,
      status: 415,
      body: { error: "unsupported_content_encoding", supported: ["identity", "gzip"] },
    };
  }

  // ─── 3. 密钥配置 ──────────────────────────────────────────────────
  const ingestExpected = env[ENV_INGEST_KEY];
  if (typeof ingestExpected !== "string" || ingestExpected.length === 0) {
    // 缺配置失败关闭，而不是放行。这是部署配置问题，不是调用方凭据问题。
    return { ok: false, status: 503, body: { error: "ingest_key_not_configured" } };
  }
  const adminExpected = env[ENV_ADMIN_KEY];
  if (typeof adminExpected === "string" && adminExpected === ingestExpected) {
    // 两种权限必须相互独立。相同密钥意味着投递方凭据可以直接查询历史日志。
    return { ok: false, status: 503, body: { error: "keys_must_differ" } };
  }

  // ─── 4. 独立 ingest key（无条件要求） ─────────────────────────────
  if (!verifySharedSecret(ingestKeyHeader, ingestExpected)) {
    return { ok: false, status: 401, body: { error: "unauthorized" } };
  }

  // ─── 5. EdgeOne 官方签名 ──────────────────────────────────────────
  const sigConfig = resolveSignatureConfig(env);
  if (sigConfig.mode === "misconfigured") {
    return { ok: false, status: 503, body: { error: "signature_config_invalid" } };
  }

  const authKeyParam = singleQueryValue(queryParams, "auth_key");
  const accessKeyParam = singleQueryValue(queryParams, "access_key");
  if (!authKeyParam.ok || !accessKeyParam.ok) {
    return { ok: false, status: 401, body: { error: "unauthorized" } };
  }
  const authKey = authKeyParam.value;
  const accessKey = accessKeyParam.value;

  if (sigConfig.mode === "enforced") {
    // 已配置即强制：缺参数不能降级绕过。
    const result = verifyEdgeOneSignature({
      uri: requestPath,
      authKey,
      accessKey,
      getSecretKey: (candidate) =>
        candidate === sigConfig.secretId ? sigConfig.secretKey : undefined,
      ...(nowSeconds !== undefined ? { nowSeconds } : {}),
    });
    if (!result.ok) {
      return { ok: false, status: 401, body: { error: "unauthorized" } };
    }
  } else if (authKey !== undefined || accessKey !== undefined) {
    // 未配置密钥却收到签名参数：无法验证，拒绝而不是忽略。
    return { ok: false, status: 401, body: { error: "unauthorized" } };
  }

  return { ok: true, gzip: encoding.kind === "gzip" };
}

/**
 * 核心接收处理。与 HTTP 框架无关，可直接单测。
 *
 * @param {object} params
 * @param {string} [params.method]
 * @param {Buffer} params.rawBody 原始正文字节（gzip 解压之前）。
 * @param {string|undefined} [params.contentEncoding] Content-Encoding 原值。
 * @param {string} params.requestPath
 * @param {URLSearchParams} params.queryParams
 * @param {string|undefined} params.ingestKeyHeader
 * @param {Record<string, string|undefined>} params.env
 * @param {{ setJSON: Function, get?: Function }} params.store
 * @param {number} [params.maxBodyBytes]
 * @param {number} [params.maxBatchBytes]
 * @param {number} [params.maxBatchRecords]
 * @param {number} [params.maxPartitions]
 * @param {number} [params.maxChunks]
 * @param {number} [params.nowSeconds]
 * @returns {Promise<{ status: number, body: object, headers?: Record<string,string> }>}
 */
export async function handleIngestRequest({
  method = "POST",
  rawBody,
  contentEncoding,
  requestPath,
  queryParams,
  ingestKeyHeader,
  env,
  store,
  maxBodyBytes = DEFAULT_MAX_INGEST_BODY_BYTES,
  maxBatchBytes = DEFAULT_MAX_BATCH_BYTES,
  maxBatchRecords = DEFAULT_MAX_BATCH_RECORDS,
  maxPartitions = DEFAULT_MAX_PARTITIONS,
  maxChunks = DEFAULT_MAX_CHUNKS,
  nowSeconds,
}) {
  // ─── 1..5. 方法 / 编码 / 配置 / 鉴权 ──────────────────────────────
  const auth = authorizeIngest({
    method,
    contentEncoding,
    requestPath,
    queryParams,
    ingestKeyHeader,
    env,
    nowSeconds,
  });
  if (!auth.ok) {
    return {
      status: auth.status,
      body: auth.body,
      ...(auth.headers !== undefined ? { headers: auth.headers } : {}),
    };
  }

  // ─── 6. 原始体积（在解压与解析之前） ──────────────────────────────
  if (rawBody.length > maxBodyBytes) {
    return { status: 413, body: { error: "payload_too_large", maxBytes: maxBodyBytes } };
  }

  // ─── 7. 解压 + 解析（有界） ───────────────────────────────────────
  let parsed;
  try {
    parsed = parseLogBody(rawBody, {
      gzip: auth.gzip,
      maxRecords: maxBatchRecords,
    });
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : undefined;
    if (
      code === LOG_BODY_ERROR_CODES.GZIP_TOO_LARGE ||
      code === LOG_BODY_ERROR_CODES.TOO_MANY_RECORDS ||
      code === LOG_BODY_ERROR_CODES.RECORD_TOO_DEEP
    ) {
      return { status: 413, body: { error: code } };
    }
    if (
      code === LOG_BODY_ERROR_CODES.GZIP_FAILED ||
      code === LOG_BODY_ERROR_CODES.EMPTY_BODY ||
      code === LOG_BODY_ERROR_CODES.INVALID_RECORD ||
      code === LOG_BODY_ERROR_CODES.UNSUPPORTED_BODY
    ) {
      // 固定分类，不回显正文片段、行内容或 zlib 原始错误。
      return { status: 400, body: { error: code } };
    }
    return { status: 500, body: { error: "internal_error" } };
  }

  // ─── 8. 脱敏 ──────────────────────────────────────────────────────
  const redacted = /** @type {Record<string, unknown>[]} */ (
    redactRecords(parsed.records)
  );

  // ─── 9. 分组 + 切块 + 全量校验（此步之前不发出任何写入） ──────────
  const { groups, missing } = groupRecordsByUtcHour(redacted);
  if (missing > 0) {
    // 有记录没有任何可用时间字段。不能用当前时间伪造分区（会破坏重投幂等），
    // 也不能悄悄丢弃，因此整批拒绝，由投递方修正字段配置后重投。
    return {
      status: 400,
      body: {
        error: "missing_record_timestamp",
        recordsWithoutTimestamp: missing,
        expected: "ISO8601 RequestTime/LogTime/EdgeEndTime with explicit offset",
      },
    };
  }
  if (groups.length === 0) {
    return { status: 400, body: { error: LOG_BODY_ERROR_CODES.EMPTY_BODY } };
  }
  if (groups.length > maxPartitions) {
    return {
      status: 413,
      body: { error: "too_many_partitions", partitions: groups.length, maxPartitions },
    };
  }

  // 信封（schemaVersion/摘要/时间戳/meta）也占字节，留出余量再切分。
  const envelopeReserve = 2048;
  const chunkBudget = Math.max(1, maxBatchBytes - envelopeReserve);
  const meta = { source: "edgeone-realtime-logs", kind: parsed.kind };

  /** @type {{ key: string, payload: object, bytes: number, recordCount: number, contentDigest: string, partitionTimestampMs: number }[]} */
  const preparedBatches = [];

  for (const group of groups) {
    // 先规范化排序，让分块只取决于内容，与投递顺序、键顺序无关。
    const canonical = /** @type {Record<string, unknown>[]} */ (
      canonicalizeRecords(group.records)
    );
    const { chunks, oversizeIndex } = chunkRecords(canonical, chunkBudget, maxBatchRecords);
    if (oversizeIndex !== null) {
      // 单条记录就超过批次上限，无法在不丢数据的前提下存储。
      return { status: 413, body: { error: "record_too_large", maxBytes: chunkBudget } };
    }

    for (const chunk of chunks) {
      if (preparedBatches.length >= maxChunks) {
        return {
          status: 413,
          body: { error: "too_many_batches", maxBatches: maxChunks },
        };
      }
      try {
        const prepared = prepareBatch({
          batchId: deriveBatchId(chunk),
          partitionTimestampMs: group.partitionTimestampMs,
          records: chunk,
          maxBatchBytes,
          maxBatchRecords,
          meta,
        });
        preparedBatches.push({ ...prepared, partitionTimestampMs: group.partitionTimestampMs });
      } catch (err) {
        const code = err && typeof err.code === "string" ? err.code : undefined;
        if (code === "BATCH_TOO_LARGE" || code === "BATCH_TOO_MANY_RECORDS") {
          return { status: 413, body: { error: "batch_too_large" } };
        }
        // 键或时间戳形状非法等：属于本次投递内容问题，整批拒绝且零写入。
        return { status: 400, body: { error: "batch_preparation_failed" } };
      }
    }
  }

  // ─── 10. 全部校验通过后才写入 ─────────────────────────────────────
  /** @type {{ key: string, status: string, recordCount: number }[]} */
  const stored = [];
  let written = 0;
  let duplicate = 0;

  for (const prepared of preparedBatches) {
    try {
      const result = await storeBatch({
        store,
        batchId: prepared.payload.batchId,
        partitionTimestampMs: prepared.partitionTimestampMs,
        records: prepared.payload.records,
        maxBatchBytes,
        maxBatchRecords,
        meta,
      });
      stored.push({
        key: result.key,
        status: result.status,
        recordCount: result.recordCount,
      });
      if (result.status === "duplicate") duplicate += 1;
      else written += 1;
    } catch (err) {
      const code = err && typeof err.code === "string" ? err.code : undefined;
      if (code === "BATCH_CONFLICT") {
        // 同一个键上已有内容不一致的对象，或读回校验失败。不能 ACK。
        return {
          status: 500,
          body: { error: "batch_conflict", storedBatches: stored.length },
        };
      }
      // 前面的批次可能已写入。返回 5xx 让 EdgeOne 重投；键由内容派生，
      // 已写入的批次会命中 duplicate，不会重复存储。
      return {
        status: 500,
        body: { error: "storage_error", storedBatches: stored.length },
      };
    }
  }

  // 官方 Python 示例（61296.md:108-120）返回 result_code/result_desc/timestamp，
  // 这里沿用同样的字段名，便于控制台连通性校验识别。
  const body = {
    result_code: 0,
    result_desc: "success",
    timestamp: Math.floor(Date.now() / 1000),
    kind: parsed.kind,
    recordCount: redacted.length,
    batchesWritten: written,
    batchesDuplicate: duplicate,
    partitions: groups.length,
    batches: stored,
  };

  const ingestExpected = env[ENV_INGEST_KEY];
  if (typeof ingestExpected === "string" && ingestExpected.length < RECOMMENDED_KEY_MIN_LENGTH) {
    body.warning = `INGEST_SHARED_KEY is shorter than the recommended ${RECOMMENDED_KEY_MIN_LENGTH} characters`;
  }

  return { status: 200, body };
}
