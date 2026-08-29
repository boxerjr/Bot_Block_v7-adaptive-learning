import test from "node:test";
import assert from "node:assert/strict";

import {
  fingerprintV63Reputation,
  networkBucket,
} from "../src/compat/v63/fingerprint.js";

class FakeD1 {
  constructor() {
    this.rows = new Map();
  }

  prepare(sql) {
    const db = this;
    return {
      args: [],
      bind(...args) {
        this.args = args;
        return this;
      },
      async first() {
        const [fingerprintId] = this.args;
        return db.rows.get(fingerprintId) || null;
      },
      async run() {
        const [fingerprintId, networksJson, seen, lastSeenMs, expiresAtMs] = this.args;
        db.rows.set(fingerprintId, {
          network_hashes_json: networksJson,
          seen,
          last_seen_ms: lastSeenMs,
          expires_at_ms: expiresAtMs,
        });
        return { success: true };
      },
    };
  }
}

const ua =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Mobile Safari/537.36";

const telemetry = {
  navigator: {
    platform: "Linux armv8l",
    vendor: "Google Inc.",
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 5,
  },
  webgl: { renderer: "Adreno 750" },
  canvas: "canvas-hash-example",
  screen: { width: 412, height: 915, dpr: 2.625 },
  timezone: { name: "Europe/Madrid" },
};

const network = { bot: { ja4: "ja4-test" } };

test("networkBucket keeps V6.3 IPv4 /24 behavior", () => {
  assert.equal(networkBucket("203.0.113.42"), "203.0.113.0/24");
});

test("networkBucket keeps V6.3 IPv6 first-four-hextets behavior", () => {
  assert.equal(
    networkBucket("2001:db8:abcd:1234:5678:9abc:def0:1111"),
    "2001:db8:abcd:1234::/64"
  );
});

test("V6.3 fingerprint risk starts at 5 networks and rises at 8", async () => {
  const db = new FakeD1();
  let result;

  for (let i = 1; i <= 8; i++) {
    result = await fingerprintV63Reputation({
      db,
      ip: `10.0.${i}.25`,
      ua,
      network,
      telemetry,
      nowMs: 1_000_000 + i,
    });

    if (i < 5) assert.equal(result.risk, 0);
    if (i === 5) {
      assert.equal(result.risk, 15);
      assert.deepEqual(result.reasons, ["fingerprint_multiple_networks"]);
    }
  }

  assert.equal(result.recentNetworks, 8);
  assert.equal(result.risk, 25);
  assert.deepEqual(result.reasons, ["fingerprint_many_networks"]);
});

test("V6.3 fingerprint remembers at most 12 recent networks", async () => {
  const db = new FakeD1();
  let result;

  for (let i = 1; i <= 15; i++) {
    result = await fingerprintV63Reputation({
      db,
      ip: `172.16.${i}.5`,
      ua,
      network,
      telemetry,
      nowMs: 2_000_000 + i,
    });
  }

  assert.equal(result.recentNetworks, 12);
  assert.equal(result.seen, 15);
  assert.equal(result.risk, 25);
});

test("expired 30-minute state resets networks and seen count", async () => {
  const db = new FakeD1();

  const first = await fingerprintV63Reputation({
    db,
    ip: "192.0.2.10",
    ua,
    network,
    telemetry,
    nowMs: 5_000_000,
  });

  const expired = await fingerprintV63Reputation({
    db,
    ip: "198.51.100.10",
    ua,
    network,
    telemetry,
    nowMs: first.expiresAtMs + 1,
  });

  assert.equal(expired.recentNetworks, 1);
  assert.equal(expired.seen, 1);
  assert.equal(expired.risk, 0);
});
