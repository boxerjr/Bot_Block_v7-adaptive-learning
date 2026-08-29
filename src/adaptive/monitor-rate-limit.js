import { networkBucket } from "../compat/v63/fingerprint.js";

function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

async function keyedBucketId(secret, ip) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`m22-rate:${networkBucket(ip)}`)
  );
  return bytesToB64url(new Uint8Array(signature)).slice(0, 18);
}

/**
 * Approximate per-network-bucket limiter for the public /check page.
 * Uses a keyed HMAC identifier; raw IP/network bucket is never persisted.
 * Reuses the existing live-session table with short-lived m22rl_ rows.
 * Fails open if D1 is temporarily unavailable so monitoring does not become
 * an accidental enforcement layer.
 */
export async function checkMonitorRateLimit({
  db,
  secret,
  ip,
  limit = 12,
  windowMs = 60_000,
  nowMs = Date.now(),
}) {
  const safeLimit = Math.max(1, Math.min(120, Number(limit) || 12));
  if (!db || !secret) {
    return { allowed: true, ready: false, limit: safeLimit, count: 0 };
  }

  try {
    const bucketId = await keyedBucketId(secret, ip || "unknown");
    const prefix = `m22rl_${bucketId}_`;
    const cutoff = nowMs - windowMs;

    const row = await db
      .prepare(
        `SELECT COUNT(*) AS n
         FROM adaptive_live_capture_sessions
         WHERE sid LIKE ?
           AND issued_at_ms >= ?`
      )
      .bind(`${prefix}%`, cutoff)
      .first();

    const count = Number(row?.n || 0);
    if (count >= safeLimit) {
      return {
        allowed: false,
        ready: true,
        limit: safeLimit,
        count,
        retryAfterSeconds: Math.max(1, Math.ceil(windowMs / 1000)),
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
           WHERE sid LIKE 'm22rl_%'
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
    };
  } catch {
    return { allowed: true, ready: false, limit: safeLimit, count: 0 };
  }
}
