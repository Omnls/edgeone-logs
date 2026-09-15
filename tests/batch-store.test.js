/**
 * tests/batch-store.test.js
 *
 * Fully offline tests for server/storage/batch-store.js using an in-memory
 * fake store. No network access, no real @edgeone/pages-blob dependency.
 *
 * Run with: node --test "tests/**\/*.test.js"
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  storeBatch,
  getBatch,
  listBatches,
  computeBatchKey,
  canonicalizeRecords,
  computeRecordsDigest,
  BatchTooManyRecordsError,
  BatchTooLargeError,
} from "../server/storage/batch-store.js";

/**
 * Minimal fake error shape mimicking the SDK's PreconditionFailedError,
 * which is a PagesBlobError subclass carrying `.code === 'PRECONDITION_FAILED'`.
 */
class FakePreconditionFailedError extends Error {
  constructor() {
    super("Precondition failed");
    this.name = "PreconditionFailedError";
    this.code = "PRECONDITION_FAILED";
  }
}

class FakeQuotaExceededError extends Error {
  constructor() {
    super("Quota exceeded");
    this.name = "QuotaExceededError";
    this.code = "QUOTA_EXCEEDED";
  }
}

/**
 * In-memory fake implementing the subset of the Store interface this module
 * depends on: setJSON, get, list. Mirrors the real SDK's key semantics:
 * - setJSON with onlyIfNew:true throws FakePreconditionFailedError if the
 *   key already exists.
 * - get returns null for missing keys (never throws for "not found").
 * - list supports prefix / directories:false / paginate:false / cursor /
 *   limit, returning a `cursor` only when there are more results.
 */
class FakeStore {
  constructor() {
    /** @type {Map<string, unknown>} */
    this.data = new Map();
  }

  async setJSON(key, value, options = {}) {
    if (options.onlyIfNew && this.data.has(key)) {
      throw new FakePreconditionFailedError();
    }
    this.data.set(key, value);
  }

  async get(key, options = {}) {
    if (!this.data.has(key)) return null;
    const value = this.data.get(key);
    if (options.type === "json" || options.type === undefined) {
      return value;
    }
    return value;
  }

  async list(options = {}) {
    assert.equal(
      options.directories,
      false,
      "listBatches must pass directories:false to the underlying store"
    );
    assert.equal(
      options.paginate,
      false,
      "listBatches must pass paginate:false to the underlying store"
    );

    const prefix = options.prefix ?? "";
    const allKeys = [...this.data.keys()]
      .filter((k) => k.startsWith(prefix))
      .sort(); // deterministic order for test pagination, not a store guarantee

    let startIndex = 0;
    if (options.cursor !== undefined) {
      const idx = allKeys.indexOf(options.cursor);
      startIndex = idx === -1 ? 0 : idx + 1;
    }

    const limit = options.limit ?? allKeys.length;
    const page = allKeys.slice(startIndex, startIndex + limit);
    const hasMore = startIndex + limit < allKeys.length;

    return {
      blobs: page.map((key) => ({ key, etag: `etag-${key}` })),
      directories: [],
      ...(hasMore ? { cursor: page[page.length - 1] } : {}),
    };
  }
}

function makeRecords(n) {
  return Array.from({ length: n }, (_, i) => ({
    status: 522,
    host: "example.test",
    requestId: `req-${i}`,
  }));
}

describe("storeBatch: first write", () => {
  test("returns status 'written' on first write and stores the payload", async () => {
    const store = new FakeStore();
    const partitionTimestampMs = Date.UTC(2026, 8, 12, 10, 30, 0); // 2026-09-12T10:30:00Z

    const result = await storeBatch({
      store,
      batchId: "abc123",
      partitionTimestampMs,
      records: makeRecords(3),
    });

    assert.equal(result.status, "written");
    assert.equal(result.key, "logs/2026-09-12/10/abc123.json");
    assert.equal(result.recordCount, 3);
    assert.ok(store.data.has(result.key));
  });
});

describe("storeBatch: duplicate detection", () => {
  test("repeated write with same batchId + partition timestamp returns 'duplicate', not an error", async () => {
    const store = new FakeStore();
    const partitionTimestampMs = Date.UTC(2026, 8, 12, 10, 30, 0);
    const records = makeRecords(3);

    const first = await storeBatch({
      store,
      batchId: "dup1",
      partitionTimestampMs,
      records,
    });
    assert.equal(first.status, "written");

    const second = await storeBatch({
      store,
      batchId: "dup1",
      partitionTimestampMs,
      records,
    });
    assert.equal(second.status, "duplicate");
    assert.equal(second.key, first.key);
  });
});

describe("storeBatch: non-precondition errors propagate", () => {
  test("a non-PRECONDITION_FAILED error from the store is rethrown, not swallowed", async () => {
    const store = new FakeStore();
    store.setJSON = async () => {
      throw new FakeQuotaExceededError();
    };

    await assert.rejects(
      () =>
        storeBatch({
          store,
          batchId: "quota1",
          partitionTimestampMs: Date.UTC(2026, 8, 12, 10, 0, 0),
          records: makeRecords(1),
        }),
      (err) => {
        assert.equal(err.code, "QUOTA_EXCEEDED");
        return true;
      }
    );
  });
});

describe("storeBatch: cross-hour retry idempotency", () => {
  test("same batch identity + same batch-intrinsic partition timestamp lands on the same key across a simulated hour-boundary retry", async () => {
    const store = new FakeStore();
    // Simulate: the log records themselves say the batch's own time is
    // 23:59:58 UTC on 2026-09-12. The first attempt is made "at" that time;
    // a retry is simulated to happen after local wall-clock has rolled over
    // to 00:01 the next day — but the partition timestamp passed in must
    // still be the batch's own (frozen) time, not "now".
    const batchIntrinsicTimestampMs = Date.UTC(2026, 8, 12, 23, 59, 58);
    const records = makeRecords(2);

    const firstAttempt = await storeBatch({
      store,
      batchId: "crosshour1",
      partitionTimestampMs: batchIntrinsicTimestampMs,
      records,
    });
    assert.equal(firstAttempt.status, "written");
    assert.equal(firstAttempt.key, "logs/2026-09-12/23/crosshour1.json");

    // Retry "later" (simulated) — caller still supplies the SAME
    // batch-intrinsic timestamp, per the documented contract.
    const retryAttempt = await storeBatch({
      store,
      batchId: "crosshour1",
      partitionTimestampMs: batchIntrinsicTimestampMs,
      records,
    });

    assert.equal(retryAttempt.status, "duplicate");
    assert.equal(retryAttempt.key, firstAttempt.key);
    assert.equal(store.data.size, 1, "only one object should exist in storage");
  });
});

describe("storeBatch: concurrent writes to the same batch", () => {
  test("two 'concurrent' calls for the same batch: one written, one duplicate, no data corruption", async () => {
    const store = new FakeStore();
    const partitionTimestampMs = Date.UTC(2026, 8, 12, 12, 0, 0);
    const records = makeRecords(4);
    const batchId = "concurrent1";

    // Simulate concurrency deterministically: wrap setJSON so the *second*
    // logical call to reach it (regardless of Promise interleaving) sees the
    // key already present, mirroring a real race resolved by the backend's
    // atomic If-None-Match check.
    const originalSetJSON = store.setJSON.bind(store);
    let callCount = 0;
    store.setJSON = async (key, value, options) => {
      callCount += 1;
      if (callCount === 2) {
        // second arrival always loses the race
        throw new FakePreconditionFailedError();
      }
      return originalSetJSON(key, value, options);
    };

    const [resultA, resultB] = await Promise.all([
      storeBatch({ store, batchId, partitionTimestampMs, records }),
      storeBatch({ store, batchId, partitionTimestampMs, records }),
    ]);

    const statuses = [resultA.status, resultB.status].sort();
    assert.deepEqual(statuses, ["duplicate", "written"]);
    assert.equal(resultA.key, resultB.key);
    assert.equal(store.data.size, 1);
  });
});

describe("storeBatch: record count limit", () => {
  test("exceeding maxBatchRecords throws synchronously and never calls store.setJSON", async () => {
    const store = new FakeStore();
    let setJSONCalled = false;
    store.setJSON = async () => {
      setJSONCalled = true;
    };

    await assert.rejects(
      () =>
        storeBatch({
          store,
          batchId: "toomany1",
          partitionTimestampMs: Date.UTC(2026, 8, 12, 5, 0, 0),
          records: makeRecords(5),
          maxBatchRecords: 4,
        }),
      (err) => {
        assert.ok(err instanceof BatchTooManyRecordsError);
        assert.equal(err.code, "BATCH_TOO_MANY_RECORDS");
        return true;
      }
    );
    assert.equal(setJSONCalled, false);
  });
});

describe("storeBatch: byte size limit", () => {
  test("exceeding maxBatchBytes throws synchronously and never calls store.setJSON", async () => {
    const store = new FakeStore();
    let setJSONCalled = false;
    store.setJSON = async () => {
      setJSONCalled = true;
    };

    // Build a batch that serializes to more than a tiny cap.
    const records = [{ note: "x".repeat(1000) }];

    await assert.rejects(
      () =>
        storeBatch({
          store,
          batchId: "toobig1",
          partitionTimestampMs: Date.UTC(2026, 8, 12, 6, 0, 0),
          records,
          maxBatchBytes: 100, // deliberately tiny
        }),
      (err) => {
        assert.ok(err instanceof BatchTooLargeError);
        assert.equal(err.code, "BATCH_TOO_LARGE");
        return true;
      }
    );
    assert.equal(setJSONCalled, false);
  });
});

describe("listBatches: bounded pagination", () => {
  test("passes through prefix/limit/cursor and forces directories:false, paginate:false", async () => {
    const store = new FakeStore();
    const partitionTimestampMs = Date.UTC(2026, 8, 12, 8, 0, 0);

    // Seed 5 batches in the same UTC hour partition, plus one in a different
    // hour that should be excluded by prefix.
    for (let i = 0; i < 5; i += 1) {
      await storeBatch({
        store,
        batchId: `page${i}`,
        partitionTimestampMs,
        records: makeRecords(1),
      });
    }
    await storeBatch({
      store,
      batchId: "otherhour",
      partitionTimestampMs: Date.UTC(2026, 8, 12, 9, 0, 0),
      records: makeRecords(1),
    });

    const prefix = "logs/2026-09-12/08/";

    const page1 = await listBatches({ store, prefix, limit: 2 });
    assert.equal(page1.blobs.length, 2);
    assert.ok(page1.cursor, "expected a cursor since more results remain");
    assert.ok(page1.blobs.every((b) => b.key.startsWith(prefix)));

    const page2 = await listBatches({
      store,
      prefix,
      limit: 2,
      cursor: page1.cursor,
    });
    assert.equal(page2.blobs.length, 2);
    assert.ok(page2.cursor);

    const page3 = await listBatches({
      store,
      prefix,
      limit: 2,
      cursor: page2.cursor,
    });
    assert.equal(page3.blobs.length, 1);
    assert.equal(
      page3.cursor,
      undefined,
      "no cursor once all results in prefix are exhausted"
    );

    const seenKeys = new Set([
      ...page1.blobs.map((b) => b.key),
      ...page2.blobs.map((b) => b.key),
      ...page3.blobs.map((b) => b.key),
    ]);
    assert.equal(seenKeys.size, 5);
    assert.ok(![...seenKeys].some((k) => k.includes("otherhour")));
  });
});

describe("empty / not-found scenarios", () => {
  test("listBatches on an empty/no-match prefix returns an empty array, not an error", async () => {
    const store = new FakeStore();
    const result = await listBatches({ store, prefix: "logs/2099-01-01/00/" });
    assert.deepEqual(result.blobs, []);
    assert.equal(result.cursor, undefined);
  });

  test("getBatch on a missing key returns null, not an error", async () => {
    const store = new FakeStore();
    const result = await getBatch({
      store,
      key: "logs/2026-09-12/00/does-not-exist.json",
    });
    assert.equal(result, null);
  });
});

describe("computeBatchKey", () => {
  test("produces a UTC date/hour partitioned key with no sensitive fields", () => {
    const key = computeBatchKey({
      batchId: "f3a1c9",
      partitionTimestampMs: Date.UTC(2026, 8, 12, 23, 5, 0),
    });
    assert.equal(key, "logs/2026-09-12/23/f3a1c9.json");
  });

  test("rejects a batch id that looks like it could carry raw sensitive data", () => {
    assert.throws(() =>
      computeBatchKey({
        batchId: "https://example.com/secret?token=abc",
        partitionTimestampMs: Date.now(),
      })
    );
  });
});
