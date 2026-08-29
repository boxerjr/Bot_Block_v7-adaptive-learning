import {
  deriveManualIpKey,
  isManualIpBlocked,
  setManualIpBlocked,
} from "./manual-ip-block.js";

export async function clearMonitorRateLimitForIpKey(db, ipKey) {
  if (!db || !ipKey) return false;
  try {
    await db
      .prepare(
        `DELETE FROM adaptive_live_capture_sessions
         WHERE sid GLOB ?`
      )
      .bind(`m22rl_${String(ipKey)}_*`)
      .run();
    return true;
  } catch {
    return false;
  }
}

/**
 * Exact-IP public monitor limiter.
 *
 * Privacy:
 * - raw IP is never persisted
 * - the counter key is the same keyed exact-IP HMAC family used by manual block
 *
 * Enforcement:
 * - first `limit` requests inside the rolling window are allowed
 * - the next request automatically adds that exact IP HMAC to the blocklist
 * - callers should return the normal block response (404 lower layer, which the
 *   production wrapper converts to BLOCK_URL when configured)
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
  if (!db || !secret) {
    return {
      allowed: true,
      ready: false,
      limit: safeLimit,
      count: 0,
      exactIp: true,
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
        autoBlockEnabled: true,
      };
    }

    if (await isManualIpBlocked(db, ipKey, nowMs)) {
      return {
        allowed: false,
        ready: true,
        limit: safeLimit,
        count: safeLimit,
        exactIp: true,
        alreadyBlocked: true,
        autoBlocked: true,
        newlyAutoBlocked: false,
        autoBlockEnabled: true,
        ipKey,
      };
    }

    const prefix = `m22rl_${ipKey}_`;
    const cutoff = nowMs - windowMs;

    const row = await db
      .prepare(
        `SELECT COUNT(*) AS n
         FROM adaptive_live_capture_sessions
         WHERE sid GLOB ?
           AND issued_at_ms >= ?`
      )
      .bind(`${prefix}*`, cutoff)
      .first();

    const count = Number(row?.n || 0);
    if (count >= safeLimit) {
      const autoBlocked = await setManualIpBlocked(db, ipKey, "rate_limit", nowMs);
      return {
        allowed: false,
        ready: true,
        limit: safeLimit,
        count,
        retryAfterSeconds: Math.max(1, Math.ceil(windowMs / 1000)),
        exactIp: true,
        autoBlocked,
        newlyAutoBlocked: autoBlocked,
        autoBlockEnabled: true,
        ipKey,
      };
    }

    const sid = `${prefix}${nowMs}_${crypto.randomUUID()}`;
    await db
      .prepare(
        `INSERT INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, ?)`
      )
      .bind(sid, nowMs, nowMs + windowMs * 2, nowMs)
      .run();

    try {
      await db
        .prepare(
          `DELETE FROM adaptive_live_capture_sessions
           WHERE sid GLOB 'm22rl_*'
             AND expires_at_ms < ?`
        )
        .bind(nowMs)
        .run();
    } catch {}

    return {
      allowed: true,
      ready: true,
      limit: safeLimit,
      count: count + 1,
      remaining: Math.max(0, safeLimit - count - 1),
      exactIp: true,
      autoBlocked: false,
      newlyAutoBlocked: false,
      autoBlockEnabled: true,
      ipKey,
    };
  } catch {
    return {
      allowed: true,
      ready: false,
      limit: safeLimit,
      count: 0,
      exactIp: true,
      autoBlockEnabled: true,
    };
  }
}
