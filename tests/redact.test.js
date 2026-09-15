/**
 * tests/redact.test.js
 *
 * 脱敏层测试。要点：
 *   - 凭据类字段递归脱敏，包含未知的组合字段名（子串命中）。
 *   - 原始查询串默认整体移除，只保留「有/无」信号。
 *   - URL 形态字段去掉 userinfo/query/fragment，但保留 scheme/host/path。
 *   - 522 排查所需的诊断字段必须原样保留，尤其 EdgeException 的未知新取值
 *     不能被枚举丢弃。
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  REDACTED_PLACEHOLDER,
  REMOVED_QUERY_PLACEHOLDER,
  isSensitiveKey,
  isUrlLikeKey,
  redactRecord,
  redactRecords,
  sanitizeUrlLike,
} from "../server/lib/redact.js";

test("Authorization 与 Cookie 类字段被脱敏", () => {
  const out = redactRecord({
    Authorization: "Bearer abc.def.ghi",
    Cookie: "sid=1; token=2",
    "Set-Cookie": "sid=1; HttpOnly",
    RequestHost: "www.example.com",
  });
  assert.equal(out.Authorization, REDACTED_PLACEHOLDER);
  assert.equal(out.Cookie, REDACTED_PLACEHOLDER);
  assert.equal(out["Set-Cookie"], REDACTED_PLACEHOLDER);
  assert.equal(out.RequestHost, "www.example.com");
});

test("未知的组合字段名按子串命中脱敏", () => {
  const out = redactRecord({
    "X-Custom-Auth-Token": "t",
    UpstreamCookieHeader: "c",
    MyAppPassword: "p",
    SomeApiKeyValue: "k",
    HarmlessCounter: 3,
  });
  assert.equal(out["X-Custom-Auth-Token"], REDACTED_PLACEHOLDER);
  assert.equal(out.UpstreamCookieHeader, REDACTED_PLACEHOLDER);
  assert.equal(out.MyAppPassword, REDACTED_PLACEHOLDER);
  assert.equal(out.SomeApiKeyValue, REDACTED_PLACEHOLDER);
  assert.equal(out.HarmlessCounter, 3);
});

test("嵌套结构中的凭据字段同样被脱敏，且不保留内部结构", () => {
  const out = redactRecord({
    Custom: {
      Headers: { Authorization: "Bearer x", Accept: "*/*" },
      Body: { user: "u", password: "p" },
    },
  });
  assert.equal(out.Custom.Headers.Authorization, REDACTED_PLACEHOLDER);
  assert.equal(out.Custom.Headers.Accept, "*/*");
  // Body 本身是敏感字段名，整体替换，不暴露内部键。
  assert.equal(out.Custom.Body, REDACTED_PLACEHOLDER);
});

test("数组内的嵌套对象也被处理", () => {
  const out = redactRecord({
    Items: [{ token: "a" }, { RequestHost: "h" }],
  });
  assert.equal(out.Items[0].token, REDACTED_PLACEHOLDER);
  assert.equal(out.Items[1].RequestHost, "h");
});

test("原始查询串默认整体移除，但保留空值与官方占位符 -", () => {
  assert.equal(
    redactRecord({ RequestUrlQueryString: "a=1&phone=13800000000" })
      .RequestUrlQueryString,
    REMOVED_QUERY_PLACEHOLDER
  );
  // 官方样例里无查询串时是 "-"，保留原值以区分「没有」与「已删除」。
  assert.equal(
    redactRecord({ RequestUrlQueryString: "-" }).RequestUrlQueryString,
    "-"
  );
  assert.equal(
    redactRecord({ RequestUrlQueryString: "" }).RequestUrlQueryString,
    ""
  );
});

test("编码过的参数名也无法绕过：整串移除而不是逐参数匹配", () => {
  const out = redactRecord({
    RequestUrlQueryString: "%74%6f%6b%65%6e=secretvalue&id=7",
  });
  assert.equal(out.RequestUrlQueryString, REMOVED_QUERY_PLACEHOLDER);
  assert.ok(!JSON.stringify(out).includes("secretvalue"));
});

test("URL 形态字段去掉 query 与 fragment，保留路径", () => {
  const out = redactRecord({
    RequestUrl: "/en-us/about.html?token=abc#frag",
  });
  assert.equal(
    out.RequestUrl,
    `/en-us/about.html?${REMOVED_QUERY_PLACEHOLDER}#${REMOVED_QUERY_PLACEHOLDER}`
  );
  assert.ok(!out.RequestUrl.includes("abc"));
});

test("相对路径与官方 - 占位符不被改写", () => {
  assert.equal(
    redactRecord({ RequestUrl: "/en-us/about.html" }).RequestUrl,
    "/en-us/about.html"
  );
  assert.equal(redactRecord({ RequestUrl: "-" }).RequestUrl, "-");
});

test("Referer 中的 userinfo 被脱敏", () => {
  const out = redactRecord({
    RequestReferer: "https://user:pass@www.example.com/a?b=1",
  });
  assert.equal(
    out.RequestReferer,
    `https://${REDACTED_PLACEHOLDER}@www.example.com/a?${REMOVED_QUERY_PLACEHOLDER}`
  );
  assert.ok(!out.RequestReferer.includes("pass"));
});

test("sanitizeUrlLike 对无 query/fragment 的取值不加占位符", () => {
  assert.equal(
    sanitizeUrlLike("https://www.example.com/a"),
    "https://www.example.com/a"
  );
  // 只有 "?" 没有内容时不视为存在查询串。
  assert.equal(sanitizeUrlLike("https://www.example.com/a?"), "https://www.example.com/a");
});

test("522 排查所需字段原样保留，EdgeException 未知取值不丢弃", () => {
  const record = {
    EdgeResponseStatusCode: 522,
    OriginResponseStatusCode: 0,
    EdgeException: "SOME_FUTURE_ORIGIN_ERROR_CODE",
    OriginIP: "1.2.3.4",
    ClientIP: "5.6.7.8",
    RequestID: "13515444256055847385",
    RequestHost: "www.example.com",
    RequestUA: "Mozilla/5.0",
    EdgeInternalTime: 334,
  };
  const out = redactRecord(record);
  assert.deepEqual(out, record);
});

test("不修改入参，返回新对象", () => {
  const record = { Authorization: "Bearer x", Nested: { token: "t" } };
  const out = redactRecord(record);
  assert.equal(record.Authorization, "Bearer x");
  assert.equal(record.Nested.token, "t");
  assert.notEqual(out, record);
  assert.notEqual(out.Nested, record.Nested);
});

test("循环引用不会导致抛错或无限递归", () => {
  const record = { RequestHost: "h" };
  record.self = record;
  assert.doesNotThrow(() => redactRecord(record));
});

test("超深嵌套不抛错（达到深度上限后原样保留，属已知限制）", () => {
  let deep = { token: "leaf" };
  for (let i = 0; i < 20; i += 1) deep = { level: deep };
  assert.doesNotThrow(() => redactRecord(deep));
});

test("redactRecords 批量处理，非对象元素原样返回", () => {
  const out = redactRecords([{ Authorization: "a" }, 42, null]);
  assert.equal(out[0].Authorization, REDACTED_PLACEHOLDER);
  assert.equal(out[1], 42);
  assert.equal(out[2], null);
});

test("对象里的 __proto__ 自有键被保留为自有属性，不脱敏也不污染原型", () => {
  const input = JSON.parse('{"__proto__":"some-value","RequestID":"abc"}');
  assert.ok(Object.prototype.hasOwnProperty.call(input, "__proto__"));

  const out = redactRecord(input);

  assert.ok(Object.prototype.hasOwnProperty.call(out, "__proto__"));
  assert.equal(out.__proto__, "some-value");
  assert.equal(out.RequestID, "abc");
  assert.ok(JSON.stringify(out).includes('"__proto__":"some-value"'));
  // 实际原型不能被输入里的 __proto__ 取值篡改。
  assert.equal(Object.getPrototypeOf(out), Object.prototype);
});

test("redactRecords 批量处理时同样保留 __proto__ 自有键", () => {
  const input = JSON.parse('{"__proto__":"v","a":1}');
  const [out] = redactRecords([input]);
  assert.ok(Object.prototype.hasOwnProperty.call(out, "__proto__"));
  assert.equal(out.__proto__, "v");
  assert.equal(Object.getPrototypeOf(out), Object.prototype);
});

test("isSensitiveKey 与 isUrlLikeKey 的边界", () => {
  assert.ok(isSensitiveKey("Set-Cookie"));
  assert.ok(isSensitiveKey("secret_id"));
  assert.ok(!isSensitiveKey("RequestHost"));
  assert.ok(!isSensitiveKey("EdgeException"));

  assert.ok(isUrlLikeKey("RequestUrl"));
  assert.ok(isUrlLikeKey("Referer"));
  assert.ok(isUrlLikeKey("OriginUri"));
  // 原始查询串走专门分支，不当作 URL 清理。
  assert.ok(!isUrlLikeKey("RequestUrlQueryString"));
  assert.ok(!isUrlLikeKey("ClientIP"));
});
