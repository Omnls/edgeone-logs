import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  computeSignature,
  constantTimeEqual,
  verifyEdgeOneSignature,
  verifySharedSecret,
  DEFAULT_MAX_SKEW_SECONDS,
} from "../server/lib/auth.js";

describe("computeSignature / verifyEdgeOneSignature — official numeric example", () => {
  // From docs/reference/61296.md: SecretId=YourID, SecretKey=YourKey,
  // uri=/access_log/post, timestamp=1571587200, rand=0
  // string_to_sign = "/access_log/post-1571587200-0-YourKey"
  //
  // NOTE: the document's own worked example (line 165) claims
  // md5hash=1f7ffa7bff8f06bbfbe2ace0f14b7e16 for this string_to_sign, but
  // that is NOT the actual MD5 digest of that string. Independently
  // verified via both `md5sum` (coreutils) and Python's hashlib.md5 against
  // the exact string "/access_log/post-1571587200-0-YourKey": both give
  // d8079ca27f0db9157de64061e7264b8e. This is a documentation defect in
  // 61296.md, not an implementation bug — the *algorithm* description
  // (string_to_sign = "uri-timestamp-rand-SecretKey", then md5) is
  // unambiguous and is exactly what computeSignature implements; only the
  // document's own arithmetic in its worked example is wrong. Flagged in
  // .teamwork/sync/opus-to-gpt.md. These tests use the actually-correct
  // digest (d8079ca2...) so they exercise the real algorithm rather than
  // enshrining the document's incorrect number.
  const REAL_EXPECTED_MD5 = "d8079ca27f0db9157de64061e7264b8e";

  it("matches the independently-recomputed MD5 for the documented string_to_sign", () => {
    const sig = computeSignature({
      uri: "/access_log/post",
      timestamp: "1571587200",
      rand: "0",
      secretKey: "YourKey",
    });
    assert.equal(sig, REAL_EXPECTED_MD5);
  });

  it("verifies successfully end-to-end with the documented uri/timestamp/rand/secret", () => {
    const authKey = `1571587200-0-${REAL_EXPECTED_MD5}`;
    const result = verifyEdgeOneSignature({
      uri: "/access_log/post",
      authKey,
      accessKey: "YourID",
      getSecretKey: (accessKey) =>
        accessKey === "YourID" ? "YourKey" : undefined,
      nowSeconds: 1571587200, // exactly at timestamp, zero skew
    });
    assert.deepEqual(result, { ok: true });
  });
});

describe("verifyEdgeOneSignature — rejection paths", () => {
  const REAL_EXPECTED_MD5 = "d8079ca27f0db9157de64061e7264b8e";
  const goodAuthKey = `1571587200-0-${REAL_EXPECTED_MD5}`;
  const getSecretKey = (accessKey) =>
    accessKey === "YourID" ? "YourKey" : undefined;

  it("rejects when the timestamp has expired beyond the allowed skew", () => {
    const result = verifyEdgeOneSignature({
      uri: "/access_log/post",
      authKey: goodAuthKey,
      accessKey: "YourID",
      getSecretKey,
      nowSeconds: 1571587200 + DEFAULT_MAX_SKEW_SECONDS + 1,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "timestamp_expired");
  });

  it("accepts at exactly the skew boundary", () => {
    const result = verifyEdgeOneSignature({
      uri: "/access_log/post",
      authKey: goodAuthKey,
      accessKey: "YourID",
      getSecretKey,
      nowSeconds: 1571587200 + DEFAULT_MAX_SKEW_SECONDS,
    });
    assert.equal(result.ok, true);
  });

  it("rejects an unknown access_key (SecretId)", () => {
    const result = verifyEdgeOneSignature({
      uri: "/access_log/post",
      authKey: goodAuthKey,
      accessKey: "SomeoneElsesID",
      getSecretKey,
      nowSeconds: 1571587200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "unknown_access_key");
  });

  it("rejects on signature mismatch (wrong hash for correct id/timestamp/rand)", () => {
    const tamperedAuthKey = "1571587200-0-00000000000000000000000000000000";
    const result = verifyEdgeOneSignature({
      uri: "/access_log/post",
      authKey: tamperedAuthKey,
      accessKey: "YourID",
      getSecretKey,
      nowSeconds: 1571587200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "signature_mismatch");
  });

  it("rejects on signature mismatch when the uri differs from what was signed", () => {
    const result = verifyEdgeOneSignature({
      uri: "/some/other/path",
      authKey: goodAuthKey,
      accessKey: "YourID",
      getSecretKey,
      nowSeconds: 1571587200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "signature_mismatch");
  });

  it("never throws for missing uri/authKey/accessKey", () => {
    assert.doesNotThrow(() => {
      const r1 = verifyEdgeOneSignature({
        uri: undefined,
        authKey: goodAuthKey,
        accessKey: "YourID",
        getSecretKey,
      });
      assert.equal(r1.ok, false);
      const r2 = verifyEdgeOneSignature({
        uri: "/x",
        authKey: undefined,
        accessKey: "YourID",
        getSecretKey,
      });
      assert.equal(r2.ok, false);
      const r3 = verifyEdgeOneSignature({
        uri: "/x",
        authKey: goodAuthKey,
        accessKey: undefined,
        getSecretKey,
      });
      assert.equal(r3.ok, false);
    });
  });

  it("rejects a malformed auth_key (wrong number of dash-separated parts)", () => {
    const result = verifyEdgeOneSignature({
      uri: "/access_log/post",
      authKey: "1571587200-0",
      accessKey: "YourID",
      getSecretKey,
      nowSeconds: 1571587200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, "malformed_auth_key");
  });
});

describe("verifySharedSecret — fail-closed independent ingest/admin key", () => {
  it("fails closed when expected secret is missing/undefined (unconfigured env var)", () => {
    assert.equal(verifySharedSecret("anything", undefined), false);
    assert.equal(verifySharedSecret("anything", ""), false);
  });

  it("fails closed when provided secret is missing", () => {
    assert.equal(verifySharedSecret(undefined, "configured-secret"), false);
    assert.equal(verifySharedSecret("", "configured-secret"), false);
  });

  it("accepts an exact match", () => {
    assert.equal(verifySharedSecret("configured-secret", "configured-secret"), true);
  });

  it("rejects a wrong value", () => {
    assert.equal(verifySharedSecret("wrong-secret", "configured-secret"), false);
  });
});

describe("constantTimeEqual", () => {
  it("returns true for identical strings", () => {
    assert.equal(constantTimeEqual("abc123", "abc123"), true);
  });

  it("returns false for different strings of the same length", () => {
    assert.equal(constantTimeEqual("abc123", "abc124"), false);
  });

  it("returns false for different-length strings without throwing", () => {
    assert.doesNotThrow(() => {
      assert.equal(constantTimeEqual("short", "much-longer-string"), false);
    });
  });
});
