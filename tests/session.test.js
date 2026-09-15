import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import {
  createSessionToken,
  verifySessionToken,
  SESSION_TTL_MS,
  SESSION_COOKIE_NAME,
} from "../server/lib/session.js";

const SECRET = "test-secret-value";

describe("createSessionToken / verifySessionToken — happy path", () => {
  it("a freshly created token verifies successfully with the same secret", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    assert.equal(verifySessionToken({ token, secret: SECRET, now }), true);
  });

  it("verifies just before expiry (now + ttl - 1ms)", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    const justBefore = now + SESSION_TTL_MS - 1;
    assert.equal(
      verifySessionToken({ token, secret: SECRET, now: justBefore }),
      true,
    );
  });

  it("exports the documented 12-hour TTL constant", () => {
    assert.equal(SESSION_TTL_MS, 12 * 60 * 60 * 1000);
  });

  it("exports a cookie name constant", () => {
    assert.equal(typeof SESSION_COOKIE_NAME, "string");
    assert.ok(SESSION_COOKIE_NAME.length > 0);
  });
});

describe("verifySessionToken — expiry", () => {
  it("rejects a token at exactly its expiry timestamp", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    assert.equal(
      verifySessionToken({ token, secret: SECRET, now: now + SESSION_TTL_MS }),
      false,
    );
  });

  it("rejects a token well past its expiry", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    const later = now + SESSION_TTL_MS + 60_000;
    assert.equal(verifySessionToken({ token, secret: SECRET, now: later }), false);
  });

  it("respects a custom ttlMs", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now, ttlMs: 1000 });
    assert.equal(verifySessionToken({ token, secret: SECRET, now: now + 999 }), true);
    assert.equal(verifySessionToken({ token, secret: SECRET, now: now + 1000 }), false);
  });
});

describe("verifySessionToken — tampering", () => {
  it("rejects a token with a tampered payload segment", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    const [payloadB64, hmacB64] = token.split(".");
    const tamperedPayload = Buffer.from(
      JSON.stringify({ exp: now + SESSION_TTL_MS * 100 }),
      "utf8",
    ).toString("base64url");
    const tampered = `${tamperedPayload}.${hmacB64}`;
    assert.notEqual(tamperedPayload, payloadB64);
    assert.equal(verifySessionToken({ token: tampered, secret: SECRET, now }), false);
  });

  it("rejects a token with a tampered signature segment", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    const [payloadB64, hmacB64] = token.split(".");
    // flip a character in the hmac segment while keeping it valid base64url
    const flippedChar = hmacB64[0] === "A" ? "B" : "A";
    const tamperedHmac = flippedChar + hmacB64.slice(1);
    const tampered = `${payloadB64}.${tamperedHmac}`;
    assert.equal(verifySessionToken({ token: tampered, secret: SECRET, now }), false);
  });
});

describe("verifySessionToken — wrong secret", () => {
  it("rejects a token verified against a different secret", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    assert.equal(
      verifySessionToken({ token, secret: "a-different-secret", now }),
      false,
    );
  });

  it("rejects when secret is empty string", () => {
    const now = 1700000000000;
    const token = createSessionToken({ secret: SECRET, now });
    assert.equal(verifySessionToken({ token, secret: "", now }), false);
  });
});

describe("verifySessionToken — malformed tokens never throw", () => {
  const now = 1700000000000;

  const malformedCases = [
    ["empty string", ""],
    ["no dot separator", "abcdefgh"],
    ["two dots", "abc.def.ghi"],
    ["empty payload segment", ".abcdef"],
    ["empty hmac segment", "abcdef."],
    ["non-base64url payload (contains '+')", "abc+def.ghijkl"],
    ["non-base64url hmac (contains '/')", "abcdef.ghi/jkl"],
    ["payload is not valid base64url JSON", "bm90LWpzb24.ghijklmnop"],
    [null, null],
    [undefined, undefined],
    [123, 123],
    [{}, {}],
  ];

  for (const [label, value] of malformedCases) {
    it(`rejects without throwing: ${String(label)}`, () => {
      assert.doesNotThrow(() => {
        const result = verifySessionToken({ token: value, secret: SECRET, now });
        assert.equal(result, false);
      });
    });
  }

  it("rejects a payload that is valid base64url/JSON but not an object", () => {
    const payloadB64 = Buffer.from(JSON.stringify([1, 2, 3]), "utf8").toString(
      "base64url",
    );
    // hmac doesn't matter here since payload shape is checked, but must still
    // be well-formed base64url so we exercise the payload-shape check path.
    const bogusHmac = Buffer.from("x", "utf8").toString("base64url");
    const token = `${payloadB64}.${bogusHmac}`;
    assert.doesNotThrow(() => {
      assert.equal(verifySessionToken({ token, secret: SECRET, now }), false);
    });
  });

  it("rejects a payload object missing `exp`", () => {
    // Build a token whose HMAC is actually valid for a payload without `exp`,
    // to prove the exp-shape check (not just the signature check) rejects it.
    const payloadB64 = Buffer.from(JSON.stringify({ foo: "bar" }), "utf8").toString(
      "base64url",
    );
    const hmacB64 = createHmac("sha256", SECRET)
      .update(payloadB64, "utf8")
      .digest()
      .toString("base64url");
    const token = `${payloadB64}.${hmacB64}`;
    assert.doesNotThrow(() => {
      assert.equal(verifySessionToken({ token, secret: SECRET, now }), false);
    });
  });

  it("createSessionToken throws on invalid secret (not part of verify's never-throw contract)", () => {
    assert.throws(() => createSessionToken({ secret: "", now }), TypeError);
    assert.throws(() => createSessionToken({ secret: undefined, now }), TypeError);
  });

  it("createSessionToken throws on invalid ttlMs", () => {
    assert.throws(
      () => createSessionToken({ secret: SECRET, now, ttlMs: 0 }),
      TypeError,
    );
    assert.throws(
      () => createSessionToken({ secret: SECRET, now, ttlMs: -1 }),
      TypeError,
    );
    assert.throws(
      () => createSessionToken({ secret: SECRET, now, ttlMs: NaN }),
      TypeError,
    );
  });
});
