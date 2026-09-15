/**
 * server/lib/redact.js
 *
 * 默认脱敏：在日志记录写入 Blob 之前递归清理凭据类字段与 URL 中的敏感部分。
 *
 * 设计原则
 *
 * 1. 排查 522 等源站错误必须保留的诊断信息一律不动：各类状态码
 *    （EdgeResponseStatusCode、OriginResponseStatusCode 等）、Origin* 全部字段、
 *    EdgeException、RequestID、RequestHost、RequestUrl 的路径部分、ClientIP、
 *    各类耗时与字节数。EdgeException 的取值不做白名单枚举，官方将来新增
 *    取值也会原样保留。
 * 2. 凭据类字段按「字段名」递归判定，不看取值。未知字段只要名字命中凭据模式
 *    就脱敏；名字没有明显敏感性的未知诊断字段原样保留，不做「未知即丢弃」。
 * 3. 原始查询串默认不落盘。RequestUrlQueryString 携带的是客户端原样查询串，
 *    可能含 token、手机号、身份证号等，且参数名可能是百分号编码的，无法靠
 *    参数名白名单可靠识别，因此默认整体替换为占位符，只保留「有/无查询串」
 *    这一信号。
 * 4. URL 形态字段（RequestUrl、RequestReferer、各类 *Url、Location）去掉
 *    userinfo、query、fragment，只保留 scheme/host/path，并用占位符标注被移除
 *    的部分，便于阅读者知道确有内容被删而不是原本为空。
 *
 * 本模块不抛异常，输入原对象不被修改（返回新对象）。
 */

/** 被移除内容的统一占位符。 */
export const REDACTED_PLACEHOLDER = "[REDACTED]";

/** 查询串被整体移除时的占位符。 */
export const REMOVED_QUERY_PLACEHOLDER = "[REMOVED]";

/**
 * 超过递归深度上限时的占位符。
 *
 * 关键点：达到深度上限后**不能**把剩余子树原样保留——那等于给攻击者一条
 * 绕过脱敏的路径（把凭据塞到足够深的位置即可原样落盘）。这里用占位符整体
 * 替换，宁可丢掉过深的诊断信息，也不放过未经检查的内容。
 */
export const TRUNCATED_PLACEHOLDER = "[TRUNCATED_DEPTH]";

/**
 * 递归深度上限。与 parse-log-body.js 的 DEFAULT_MAX_RECORD_DEPTH 保持同量级：
 * 解析层已经拒绝了超过该深度的记录，所以正常日志不会触达这里的上限，此处
 * 只作为独立的兜底防线。
 */
const MAX_DEPTH = 32;

/**
 * 归一化字段名：转小写并去掉分隔符，使 `X-Auth-Token`、`x_auth_token`、
 * `xAuthToken` 归一为同一形式，便于统一判定。
 *
 * @param {string} key
 * @returns {string}
 */
function normalizeKey(key) {
  return key.toLowerCase().replace(/[-_\s.]/g, "");
}

/**
 * 精确命中即脱敏的字段名（已归一化）。
 */
const SENSITIVE_EXACT = new Set([
  "authorization",
  "proxyauthorization",
  "wwwauthenticate",
  "cookie",
  "cookies",
  "setcookie",
  "token",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "bearer",
  "apikey",
  "apitoken",
  "appkey",
  "appsecret",
  "secret",
  "secretid",
  "secretkey",
  "clientsecret",
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "credential",
  "credentials",
  "session",
  "sessionid",
  "sessionkey",
  "authkey",
  "accesskey",
  "signature",
  "sign",
  "sig",
  "privatekey",
  "publickey",
  "csrftoken",
  "xsrftoken",
  "body",
  "requestbody",
  "responsebody",
  "postbody",
  "payload",
]);

/**
 * 子串命中即脱敏的模式（已归一化后匹配），用于覆盖未知的组合字段名，
 * 例如 `X-Custom-Auth-Token`、`UpstreamCookieHeader`、`MyAppPassword`。
 */
const SENSITIVE_SUBSTRINGS = [
  "authorization",
  "cookie",
  "token",
  "secret",
  "password",
  "passwd",
  "credential",
  "privatekey",
  "apikey",
];

/**
 * 判断字段名是否属于凭据类。只看名字，不看取值。
 *
 * @param {string} key
 * @returns {boolean}
 */
export function isSensitiveKey(key) {
  if (typeof key !== "string" || key.length === 0) return false;
  const n = normalizeKey(key);
  if (SENSITIVE_EXACT.has(n)) return true;
  return SENSITIVE_SUBSTRINGS.some((s) => n.includes(s));
}

/**
 * 判断字段名是否为 URL 形态字段，需要清理 userinfo/query/fragment。
 *
 * @param {string} key
 * @returns {boolean}
 */
export function isUrlLikeKey(key) {
  if (typeof key !== "string" || key.length === 0) return false;
  const n = normalizeKey(key);
  if (n === "referer" || n === "referrer" || n === "location") return true;
  if (n === "requestreferer" || n === "requestreferrer") return true;
  // 注意：requesturlquerystring 由专门分支处理，不走 URL 清理。
  if (n === "requesturlquerystring") return false;
  return n.endsWith("url") || n.endsWith("uri");
}

/**
 * 清理 URL 形态取值：移除 fragment、query 与 userinfo，保留 scheme/host/path。
 * 被移除的部分用占位符标注，避免「原本没有」与「已被删除」混淆。
 *
 * 不使用 `new URL()`：日志里的取值可能是相对路径（官方示例 RequestUrl 为
 * `/en-us/about.html`）、可能是 `-`、也可能不是严格合法 URL，构造 URL 会抛错
 * 或被规范化改写。这里只做定位切分，不重写其余字节。
 *
 * @param {string} value
 * @returns {string}
 */
export function sanitizeUrlLike(value) {
  if (typeof value !== "string" || value.length === 0) return value;
  if (value === "-") return value;

  let rest = value;
  let hadFragment = false;
  let hadQuery = false;

  const hashIdx = rest.indexOf("#");
  if (hashIdx !== -1) {
    hadFragment = rest.length > hashIdx + 1;
    rest = rest.slice(0, hashIdx);
  }

  const qIdx = rest.indexOf("?");
  if (qIdx !== -1) {
    hadQuery = rest.length > qIdx + 1;
    rest = rest.slice(0, qIdx);
  }

  // 去掉 scheme://user:pass@ 中的 userinfo。
  rest = rest.replace(
    /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/@]*@/,
    (_m, scheme) => scheme + REDACTED_PLACEHOLDER + "@"
  );

  // 协议相对 URL（//user:pass@host/path）同样要清理 userinfo。上一条正则要求
  // 显式 scheme，命中不了这种形态，会把凭据原样留在存储里。
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rest)) {
    rest = rest.replace(
      /^(\/\/)[^/@]*@/,
      (_m, slashes) => slashes + REDACTED_PLACEHOLDER + "@"
    );
  }

  let out = rest;
  if (hadQuery) out += "?" + REMOVED_QUERY_PLACEHOLDER;
  if (hadFragment) out += "#" + REMOVED_QUERY_PLACEHOLDER;
  return out;
}

/**
 * 递归脱敏任意取值。
 *
 * @param {unknown} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {unknown}
 */
function redactValue(value, depth, seen) {
  if (value === null || typeof value !== "object") return value;
  // 到达深度上限：整体替换，不把未检查的子树原样放过。
  if (depth >= MAX_DEPTH) return TRUNCATED_PLACEHOLDER;
  // 循环引用同样不能原样返回（原样返回会把未脱敏的对象引用带出去）。
  if (seen.has(value)) return TRUNCATED_PLACEHOLDER;
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((v) => redactValue(v, depth + 1, seen));
  }

  /** @type {Record<string, unknown>} */
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    // 不能用 out[k] = ...：k 为 "__proto__" 时这是对 out 原型的内建 setter，
    // 而不是创建自有属性，字段会静默消失。defineProperty 总是创建自有属性。
    Object.defineProperty(out, k, {
      value: redactField(k, v, depth, seen),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * 按字段名决定单个字段如何处理。
 *
 * @param {string} key
 * @param {unknown} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {unknown}
 */
function redactField(key, value, depth, seen) {
  const n = normalizeKey(key);

  // 原始查询串默认整体移除，只保留「有/无」信号。
  if (n === "requesturlquerystring") {
    if (typeof value !== "string") return REMOVED_QUERY_PLACEHOLDER;
    if (value === "" || value === "-") return value;
    return REMOVED_QUERY_PLACEHOLDER;
  }

  // 凭据类字段：无论取值是标量还是嵌套结构，一律替换为占位符，
  // 不保留其内部结构（结构本身也可能泄漏取值形状）。
  if (isSensitiveKey(key)) {
    return REDACTED_PLACEHOLDER;
  }

  if (isUrlLikeKey(key) && typeof value === "string") {
    return sanitizeUrlLike(value);
  }

  return redactValue(value, depth + 1, seen);
}

/**
 * 对单条已解析日志记录做默认脱敏，返回新对象，不修改入参。
 *
 * @param {Record<string, unknown>} record
 * @returns {Record<string, unknown>}
 */
export function redactRecord(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    return record;
  }
  return /** @type {Record<string, unknown>} */ (
    redactValue(record, 0, new WeakSet())
  );
}

/**
 * 批量脱敏。非对象元素原样返回。
 *
 * @param {unknown[]} records
 * @returns {unknown[]}
 */
export function redactRecords(records) {
  return records.map((r) => redactRecord(/** @type {any} */ (r)));
}

/** 供测试与文档引用的规则清单。 */
export const SENSITIVE_KEY_EXACT_NAMES = Array.from(SENSITIVE_EXACT);
export const SENSITIVE_KEY_SUBSTRINGS = SENSITIVE_SUBSTRINGS.slice();
