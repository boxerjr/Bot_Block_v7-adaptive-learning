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

function globPrefix(pattern) {
  const value = String(pattern || "");
  return value.endsWith("*") ? value.slice(0, -1) : value;
}

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
              if (statement.includes("ON CONFLICT(sid) DO UPDATE") && statement.includes("RETURNING consumed_at_ms AS n")) {
                const [sidRaw, nowRaw, expiresRaw] = args;
                const sid = String(sidRaw);
                const now = Number(nowRaw);
                const expires = Number(expiresRaw);
                const existing = rows.get(sid);

                if (!existing || Number(existing.expires_at_ms) <= now) {
                  const row = {
                    sid,
                    issued_at_ms: now,
                    expires_at_ms: expires,
                    consumed_at_ms: 1,
                  };
                  rows.set(sid, row);
                  return { n: 1, issued_at_ms: now, expires_at_ms: expires };
                }

                existing.consumed_at_ms = Number(existing.consumed_at_ms || 0) + 1;
                rows.set(sid, existing);
                return {
                  n: existing.consumed_at_ms,
                  issued_at_ms: existing.issued_at_ms,
                  expires_at_ms: existing.expires_at_ms,
                };
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
              if (statement.includes("INSERT OR REPLACE INTO adaptive_live_capture_sessions")) {
                const [sid, issuedAt, expiresAt, consumedAt] = args;
                rows.set(String(sid), {
                  sid: String(sid),
                  issued_at_ms: Number(issuedAt),
                  expires_at_ms: Number(expiresAt),
                  consumed_at_ms: consumedAt == null ? null : Number(consumedAt),
                });
                return { success: true };
              }

              if (statement.includes("DELETE FROM adaptive_live_capture_sessions") && statement.includes("sid = ? OR sid GLOB ?")) {
                const exact = String(args[0] || "");
                const prefix = globPrefix(args[1]);
                for (const sid of [...rows.keys()]) {
                  if (sid === exact || sid.startsWith(prefix)) rows.delete(sid);
                }
                return { success: true };
              }

              if (statement.includes("DELETE FROM adaptive_live_capture_sessions") && statement.includes("WHERE sid = ?")) {
                rows.delete(String(args[0] || ""));
                return { success: true };
              }

              if (statement.includes("sid GLOB 'm22rlc_*'") && statement.includes("expires_at_ms < ?")) {
                const cutoff = Number(args[0] || 0);
                for (const [sid, row] of rows.entries()) {
                  if (sid.startsWith("m22rlc_") && row.expires_at_ms < cutoff) rows.delete(sid);
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

test("first three requests pass and fourth atomically auto-blocks only the exact IP", async () => {
  const db = fakeDb();
  const secret = "rate-limit-test-secret";
  const ip = "203.0.113.10";
  const otherIp = "203.0.113.11";
  const base = 1_800_000_000_000;

  for (let i = 0; i < 3; i++) {
    const result = await checkMonitorRateLimit({ db, secret, ip, limit: 3, windowMs: 60_000, nowMs: base + i });
    assert.equal(result.allowed, true);
    assert.equal(result.count, i + 1);
    assert.equal(result.atomicCounter, true);
  }

  const fourth = await checkMonitorRateLimit({ db, secret, ip, limit: 3, windowMs: 60_000, nowMs: base + 3 });
  assert.equal(fourth.allowed, false);
  assert.equal(fourth.count, 4);
  assert.equal(fourth.autoBlocked, true);
  assert.equal(fourth.newlyAutoBlocked, true);

  const ipKey = await deriveManualIpKey(secret, ip);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 4), true);

  const other = await checkMonitorRateLimit({ db, secret, ip: otherIp, limit: 3, nowMs: base + 4 });
  assert.equal(other.allowed, true);
  assert.equal(other.count, 1);

  const otherKey = await deriveManualIpKey(secret, otherIp);
  assert.notEqual(otherKey, ipKey);
  assert.equal(await isManualIpBlocked(db, otherKey, base + 4), false);
});

test("parallel requests cannot all observe the same pre-increment count", async () => {
  const db = fakeDb();
  const secret = "parallel-rate-limit-secret";
  const ip = "198.51.100.77";
  const base = 1_800_000_050_000;

  const results = await Promise.all(
    Array.from({ length: 10 }, (_, index) =>
      checkMonitorRateLimit({
        db,
        secret,
        ip,
        limit: 3,
        windowMs: 60_000,
        nowMs: base + index,
      })
    )
  );

  assert.equal(results.filter((result) => result.allowed).length, 3);
  assert.equal(results.some((result) => result.count === 4 && result.allowed === false), true);
  const ipKey = await deriveManualIpKey(secret, ip);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 20), true);
});

test("unblock clears the atomic counter so access is really restored", async () => {
  const db = fakeDb();
  const secret = "rate-limit-test-secret";
  const ip = "198.51.100.20";
  const base = 1_800_000_100_000;

  for (let i = 0; i < 4; i++) {
    await checkMonitorRateLimit({ db, secret, ip, limit: 3, windowMs: 60_000, nowMs: base + i });
  }

  const ipKey = await deriveManualIpKey(secret, ip);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 5), true);
  assert.equal(await clearManualIpBlocked(db, ipKey), true);
  assert.equal(await clearMonitorRateLimitForIpKey(db, ipKey), true);
  assert.equal(await isManualIpBlocked(db, ipKey, base + 6), false);

  const afterUnblock = await checkMonitorRateLimit({ db, secret, ip, limit: 3, windowMs: 60_000, nowMs: base + 6 });
  assert.equal(afterUnblock.allowed, true);
  assert.equal(afterUnblock.count, 1);
  assert.equal(afterUnblock.autoBlocked, false);
});
