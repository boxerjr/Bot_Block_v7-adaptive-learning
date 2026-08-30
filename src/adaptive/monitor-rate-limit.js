import {
  deriveManualIpKey,
  isManualIpBlocked,
  setManualIpBlocked,
} from "./manual-ip-block.js";

function counterSid(ipKey) {
  return `m22rlc_${String(ipKey || "")}`;
}

export async function clearMonitorRateLimitForIpKey(db, ipKey) {
  if (!db || !ipKey) return false;
  try {
    await db
      .prepare(
        `DELETE FROM adaptive_live_capture_sessions
         WHERE sid = ? OR sid GLOB ?`
      )
      .bind(counterSid(ipKey), `m22rl_${String(ipKey)}_*`)
      .run();
    return true;
  } catch {
    return false;
  }
}

async function incrementAtomicCounter(db, ipKey, nowMs, windowMs) {
  const sid = counterSid(ipKey);
  const expiresAt = nowMs + windowMs;

  // One SQLite statement performs reset-or-increment and returns the committed
  // count. Concurrent requests serialize on the same primary-key row, so two
  // requests cannot both observe the same pre-increment count.
  return db
    .prepare(
      `INSERT INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
       VALUES (?, ?, ?, 1)
       ON CONFLICT(sid) DO UPDATE SET
         consumed_at_ms = CASE
           WHEN adaptive_live_capture_sessions.expires_at_ms <= excluded.issued_at_ms THEN 1
           ELSE COALESCE(adaptive_live_capture_sessions.consumed_at_ms, 0) + 1
         END,
         issued_at_ms = CASE
           WHEN adaptive_live_capture_sessions.expires_at_ms <= excluded.issued_at_ms
             THEN excluded.issued_at_ms
           ELSE adaptive_live_capture_sessions.issued_at_ms
         END,
         expires_at_ms = CASE
           WHEN adaptive_live_capture_sessions.expires_at_ms <= excluded.issued_at_ms
             THEN excluded.expires_at_ms
           ELSE adaptive_live_capture_sessions.expires_at_ms
         END
       RETURNING consumed_at_ms AS n, issued_at_ms, expires_at_ms`
    )
    .bind(sid, nowMs, expiresAt)
    .first();
}

/**
 * Exact-IP public monitor limiter.
 *
 * Privacy:
 * - raw IP is never persisted
 * - the counter key is the same keyed exact-IP HMAC family used by manual block
 *
 * Enforcement:
 * - the first `limit` requests inside the active window are allowed
 * - request `limit + 1` atomically crosses the threshold and blocks the exact IP
 * - the block is persistent until explicit UNBLOCK
 *
 * Fails open only when D1 / secret infrastructure is unavailable.
 */
export async function checkMonitorRateLimit({
  db,
  secret,
  ip,
  limit = 3,
  windowMs = 60_000,
  nowMs = Date.now(),
}) {
  const safeLimit = Math.max(1, Math.min(120, Number(limit) || 3));
  const safeWindowMs = Math.max(1_000, Math.min(3_600_000, Number(windowMs) || 60_000));
  if (!db || !secret) {
    return {
      allowed: true,
      ready: false,
      limit: safeLimit,
      count: 0,
      exactIp: true,
      atomicCounter: true,
      autoBlockEnabled: true,
    };
  }

  try {
    const ipKey = await deriveManualIpKey(secret, ip || "unknown");
    if (!ipKey) {
      return {
        allowed: true,
        ready: false,
        limit: safeLimit,
        count: 0,
        exactIp: true,
        atomicCounter: true,
        autoBlockEnabled: true,
      };
    }

    if (await isManualIpBlocked(db, ipKey, nowMs)) {
      return {
        allowed: false,
        ready: true,
        limit: safeLimit,
        count: safeLimit + 1,
        exactIp: true,
        atomicCounter: true,
        alreadyBlocked: true,
        autoBlocked: true,
        newlyAutoBlocked: false,
        autoBlockEnabled: true,
        ipKey,
      };
    }

    const row = await incrementAtomicCounter(db, ipKey, nowMs, safeWindowMs);
    const count = Math.max(0, Number(row?.n || 0));
    const windowExpiresAt = Number(row?.expires_at_ms || nowMs + safeWindowMs);

    if (count > safeLimit) {
      const autoBlocked = await setManualIpBlocked(db, ipKey, "rate_limit", nowMs);
      return {
        allowed: false,
        ready: true,
        limit: safeLimit,
        count,
        retryAfterSeconds: Math.max(1, Math.ceil((windowExpiresAt - nowMs) / 1000)),
        exactIp: true,
        atomicCounter: true,
        autoBlocked,
        newlyAutoBlocked: autoBlocked,
        autoBlockEnabled: true,
        ipKey,
      };
    }

    try {
      await db
        .prepare(
          `DELETE FROM adaptive_live_capture_sessions
           WHERE sid GLOB 'm22rlc_*'
             AND expires_at_ms < ?`
        )
        .bind(nowMs - safeWindowMs)
        .run();
    } catch {}

    return {
      allowed: true,
      ready: true,
      limit: safeLimit,
      count,
      remaining: Math.max(0, safeLimit - count),
      exactIp: true,
      atomicCounter: true,
      autoBlocked: false,
      newlyAutoBlocked: false,
      autoBlockEnabled: true,
      ipKey,
      windowExpiresAt,
    };
  } catch {
    return {
      allowed: true,
      ready: false,
      limit: safeLimit,
      count: 0,
      exactIp: true,
      atomicCounter: true,
      autoBlockEnabled: true,
    };
  }
}
