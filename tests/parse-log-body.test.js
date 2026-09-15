/**
 * tests/parse-log-body.test.js
 *
 * 解析层测试。关键点：官方连通性校验样例（docs/reference/61296.md:39-64）是
 * 多行缩进的单个 JSON 对象，时间字段是 ISO8601 字符串。这里逐字使用该原文，
 * 不压成单行、不把时间改成秒级数字，否则就掩盖了真实的兼容性缺陷。
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";

import {
  DEFAULT_MAX_DECOMPRESSED_BYTES,
  LOG_BODY_ERROR_CODES,
  LogBodyError,
  parseLogBody,
} from "../server/lib/parse-log-body.js";

/**
 * 捕获并返回抛出的错误对象。
 *
 * 不用 assert.throws：它的返回值是 undefined，拿不到错误对象，无法继续断言
 * 具体的 code 与 detail。
 *
 * @param {() => unknown} fn
 * @param {Function} ErrorClass
 * @returns {any}
 */
function expectError(fn, ErrorClass) {
  let caught;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  assert.ok(
    caught instanceof ErrorClass,
    `expected ${ErrorClass.name} to be thrown, got ${caught}`
  );
  return caught;
}

/** 官方连通性校验测试数据原文（61296.md:39-64），逐字保留缩进与换行。 */
const OFFICIAL_VERIFICATION_BODY = `{
    "ClientState": "CH-AH",
    "EdgeResponseTime": 366,
    "RequestID": "13515444256055847385",
    "ClientRegion": "CN",
    "RemotePort": 443,
    "RequestHost": "www.tencent.com",
    "RequestMethod": "GET",
    "RequestUrlQueryString": "-",
    "RequestUrl": "/en-us/about.html",
    "RequestProtocol": "HTTP/2.0",
    "EdgeServerID": "336d5ebc5436534e61d16e63ddfca327-d41d8cd98f00b204e9800998ecf8427e",
    "RequestTime": "2022-07-01T02:37:13Z",
    "EdgeCacheStatus": "-",
    "EdgeResponseBytes": 39430,
    "EdgeResponseStatusCode": 200,
    "ClientIP": "0.0.0.0",
    "RequestReferer": "https://www.tencent.com/",
    "RequestUA": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X)",
    "EdgeServerIP": "0.0.0.0",
    "RequestRange": "0-100/200",
    "EdgeInternalTime": 334,
    "RequestBytes": 237
}`;

test("官方连通性校验样例原文：识别为单个对象而不是 NDJSON", () => {
  const result = parseLogBody(Buffer.from(OFFICIAL_VERIFICATION_BODY, "utf8"));
  assert.equal(result.kind, "single-object");
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].RequestID, "13515444256055847385");
  // 时间字段必须原样保留 ISO8601 字符串，解析层不做时间转换。
  assert.equal(result.records[0].RequestTime, "2022-07-01T02:37:13Z");
});

test("真实 ISO8601 时间的 NDJSON 多行批次", () => {
  const body = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z","EdgeResponseStatusCode":200}',
    '{"RequestID":"b","RequestTime":"2024-10-13T23:59:59Z","EdgeResponseStatusCode":522}',
  ].join("\n");
  const result = parseLogBody(Buffer.from(body, "utf8"));
  assert.equal(result.kind, "ndjson");
  assert.equal(result.records.length, 2);
  assert.equal(result.records[1].EdgeResponseStatusCode, 522);
});

test("NDJSON 兼容 CRLF 行尾与空行", () => {
  const body =
    '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}\r\n' +
    "\r\n" +
    '{"RequestID":"b","RequestTime":"2024-10-13T23:30:40Z"}\r\n';
  const result = parseLogBody(Buffer.from(body, "utf8"));
  assert.equal(result.kind, "ndjson");
  assert.equal(result.records.length, 2);
});

test("JSON 数组形态", () => {
  const body = JSON.stringify([
    { RequestID: "a", RequestTime: "2024-10-13T23:30:39Z" },
    { RequestID: "b", RequestTime: "2024-10-13T23:30:40Z" },
  ]);
  const result = parseLogBody(Buffer.from(body, "utf8"));
  assert.equal(result.kind, "json-array");
  assert.equal(result.records.length, 2);
});

test("gzip 正文按声明解压", () => {
  const body = '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}';
  const result = parseLogBody(gzipSync(Buffer.from(body, "utf8")), {
    gzip: true,
  });
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].RequestID, "a");
});

test("声明 gzip 但正文不是 gzip：报 gzip_failed，且不泄漏 zlib 原文", () => {
  const err = expectError(
    () => parseLogBody(Buffer.from("not gzip at all", "utf8"), { gzip: true }),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.GZIP_FAILED);
  assert.ok(!/zlib|incorrect header/i.test(err.detail));
});

test("gzip 解压炸弹被上限拦截", () => {
  // 10 MiB 的零字节压缩后很小，解压后远超这里设置的 1 KiB 上限。
  const bomb = gzipSync(Buffer.alloc(10 * 1024 * 1024, 0x41));
  const err = expectError(
    () => parseLogBody(bomb, { gzip: true, maxDecompressedBytes: 1024 }),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.GZIP_TOO_LARGE);
});

test("未声明 gzip 的未压缩超限正文也被拦截", () => {
  const big = Buffer.alloc(2048, 0x41);
  const err = expectError(
    () => parseLogBody(big, { maxDecompressedBytes: 1024 }),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.GZIP_TOO_LARGE);
});

test("坏行导致整批拒绝，不做部分接受", () => {
  const body = [
    '{"RequestID":"a","RequestTime":"2024-10-13T23:30:39Z"}',
    "{ this is not json",
    '{"RequestID":"c","RequestTime":"2024-10-13T23:30:41Z"}',
  ].join("\n");
  const err = expectError(
    () => parseLogBody(Buffer.from(body, "utf8")),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.INVALID_RECORD);
  // 只报行号，不回显行内容。
  assert.match(err.detail, /line 2/);
  assert.ok(!err.detail.includes("this is not json"));
});

test("数组中非对象元素导致整批拒绝", () => {
  const body = JSON.stringify([{ RequestID: "a" }, 42]);
  const err = expectError(
    () => parseLogBody(Buffer.from(body, "utf8")),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.INVALID_RECORD);
});

test("NDJSON 行是合法 JSON 但不是对象，同样整批拒绝", () => {
  const body = '{"RequestID":"a"}\n"just a string"';
  const err = expectError(
    () => parseLogBody(Buffer.from(body, "utf8")),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.INVALID_RECORD);
});

test("空正文与纯空白正文报 empty_body", () => {
  for (const raw of ["", "   \r\n  \n"]) {
    const err = expectError(
      () => parseLogBody(Buffer.from(raw, "utf8")),
      LogBodyError
    );
    assert.equal(err.code, LOG_BODY_ERROR_CODES.EMPTY_BODY);
  }
});

test("空数组报 empty_body", () => {
  const err = expectError(
    () => parseLogBody(Buffer.from("[]", "utf8")),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.EMPTY_BODY);
});

test("JSON 标量正文报 unsupported_body（不支持 CSV 等非 JSON 格式）", () => {
  const err = expectError(
    () => parseLogBody(Buffer.from("123", "utf8")),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.UNSUPPORTED_BODY);
});

test("CSV 正文被明确拒绝，不被误当作日志记录", () => {
  const body = "CH-AH,366,13515444256055847385,CN,443\n";
  const err = expectError(
    () => parseLogBody(Buffer.from(body, "utf8")),
    LogBodyError
  );
  assert.equal(err.code, LOG_BODY_ERROR_CODES.INVALID_RECORD);
});

test("默认解压上限是自设值，非平台限制", () => {
  assert.equal(DEFAULT_MAX_DECOMPRESSED_BYTES, 16 * 1024 * 1024);
});
