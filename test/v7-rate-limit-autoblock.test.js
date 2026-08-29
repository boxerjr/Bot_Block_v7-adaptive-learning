import test from "node:test";
import assert from "node:assert/strict";
import {
  checkMonitorRateLimit,
  clearMonitorRateLimitForIpKey,
} from "../src/adaptive/monitor-rate-limit.js";
import {
  clearManualIpBlocked,
  deriveManualIpKey,
  isManualIpBlocked,
} from "../src/adaptive/manual-ip-block.js";

function fakeDb() {
  const rows = new Map();

  return {
    rows,
    prepare(sql) {
      const statement = String(sql);
      return {
        bind(...args) {
          return {
            async first() {
              if (statement.includes("COUNT(*) AS n")) {
                const pattern = String(args[0] || "");
                const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
                const cutoff = Number(args[1] || 0);
                let n = 0;
                for (const row of rows.values()) {
                  if (row.sid.startsWith(prefix) && row.issued_at_ms >= cutoff) n++;
                }
                return { n };
              }

              if (statement.includes("WHERE sid = ?") && statement.includes("expires_at_ms > ?")) {
                const sid = String(args[0] || "");
                const now = Number(args[1] || 0);
                const row = rows.get(sid);
                return row && row.expires_at_ms > now ? { sid: row.sid } : null;
              }

              return null;
            },

            async run() {
              if (statement.includes("INSERT INTO adaptive_live_capture_sessions") ||
                  statement.includes("INSERT OR REPLACE INTO adaptive_live_capture_sessions")) {
                const [sid, issuedAt, expiresAt, consumedAt] = args;
                rows.set(String(sid), {
                  sid: String(sid),
                  issued_at_ms: Number(issuedAt),
                  expires_at_ms: Number(expiresAt),
                  consumed_at_ms: consumedAt == null ? null : Number(consumedAt),
                });
                return { success: true };
              }

              if (statement.includes("DELETE FROM adaptive_live_capture_sessions") && statement.includes("WHERE sid = ?")) {
                rows.delete(String(args[0] || ""));
                return { success: true };
              }

              if (statement.includes("DELETE FROM adaptive_live_capture_sessions") && statement.includes("WHERE sid GLOB ?")) {
                const pattern = String(args[0] || "");
                const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
                for (const sid of [...rows.keys()]) {
                  if (sid.startsWith(prefix)) rows.delete(sid);
                }
                return { success: true };
              }

              if (statement.includes("DELETE FROM adaptive_live_capture_sessions") && statement.includes("expires_at_ms < ?")) {
                const now = Number(args[0] || 0);
                for (const [sid, row] of rows.entries()) {
                  if (sid.startsWith("m22rl_") && row.expires_at_ms < now) rows.delete(sid);
                }
                return { success: true };
              }

              return { success: true };
            },
          };
        },
      };
    },
  };
}

test("first three requests pass and fourth auto-blocks only the exact IP", async () => {
  const db = fakeDb();
  const secret = "rate-limit-test-secret";
  const ip = "203.0.113.10";
  const otherIp = "203.0.113.11";
  const base = 1_800_000_000_000;

  for (let i = 0; i < 3; i++) {
    const result = await checkMonitorRateLimit({
      db,
      secret,
      ip,
      limit: 3,
      windowMs: 60_000,
      nowMs: base + i,
    });
    assert.equal(result.allowed, true);
    assert.equal(result.count, i + 1);
    assert.equal(result.exactIp, true);
    assert.equal(result.autoBlocked, false);
  }

  const fourth = await checkMonitorRateLimit({
    db,
    secret,
    ip,
    limit: 3,
    windowMs: 60_000,
    nowMs: base + 3,
  });
  assert.equal(fourth.allowed, false);
  assert.equal(fourth.autoBlocked, true);
  assert.equal(fourth.newlyAutoBlocked, true);
  assert.equal(fourth.exactIp, true);

  const ipKey = await deriveManualIpKey(secret, ip);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 4), true);

  const sameIpAgain = await checkMonitorRateLimit({
    db,
    secret,
    ip,
    limit: 3,
    nowMs: base + 4,
  });
  assert.equal(sameIpAgain.allowed, false);
  assert.equal(sameIpAgain.alreadyBlocked, true);

  const other = await checkMonitorRateLimit({
    db,
    secret,
    ip: otherIp,
    limit: 3,
    windowMs: 60_000,
    nowMs: base + 4,
  });
  assert.equal(other.allowed, true);
  assert.equal(other.count, 1);

  const otherKey = await deriveManualIpKey(secret, otherIp);
  assert.notEqual(otherKey, ipKey);
  assert.equal(await isManualIpBlocked(db, otherKey, base + 4), false);
});

test("unblock clears both block row and old counters so access is really restored", async () => {
  const db = fakeDb();
  const secret = "rate-limit-test-secret";
  const ip = "198.51.100.20";
  const base = 1_800_000_100_000;

  for (let i = 0; i < 4; i++) {
    await checkMonitorRateLimit({
      db,
      secret,
      ip,
      limit: 3,
      windowMs: 60_000,
      nowMs: base + i,
    });
  }

  const ipKey = await deriveManualIpKey(secret, ip);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 5), true);

  assert.equal(await clearManualIpBlocked(db, ipKey), true);
  assert.equal(await clearMonitorRateLimitForIpKey(db, ipKey), true);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 6), false);

  const afterUnblock = await checkMonitorRateLimit({
    db,
    secret,
    ip,
    limit: 3,
    windowMs: 60_000,
    nowMs: base + 6,
  });
  assert.equal(afterUnblock.allowed, true);
  assert.equal(afterUnblock.count, 1);
  assert.equal(afterUnblock.autoBlocked, false);
});
