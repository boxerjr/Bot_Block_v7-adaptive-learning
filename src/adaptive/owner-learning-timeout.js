import { getAdaptiveFeedbackForEvent } from "../storage/adaptive-d1.js";
import {
  recordOperatorFalseNegative,
  sendTelegramWithKeyboard,
  setManualIpBlocked,
} from "./manual-ip-block.js";

export const OWNER_CONFIRM_TIMEOUT_MS = 180_000;
const PENDING_PREFIX = "m22ownerpend_";

function ownerModeEnabled(env) {
  return String(env?.OWNER_LEARNING_MODE || "false").trim().toLowerCase() === "true";
}

function validEventId(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
    String(value || "")
  );
}

function validIpKey(value) {
  return /^m22ip_[A-Za-z0-9_-]{32}$/.test(String(value || ""));
}

function pendingSid(eventId, ipKey) {
  if (!validEventId(eventId) || !validIpKey(ipKey)) return null;
  return `${PENDING_PREFIX}${String(eventId).toLowerCase()}_${String(ipKey)}`;
}

function pendingGlob(eventId) {
  if (!validEventId(eventId)) return null;
  return `${PENDING_PREFIX}${String(eventId).toLowerCase()}_*`;
}

function parsePendingSid(sid) {
  const match = String(sid || "").match(
    /^m22ownerpend_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})_(m22ip_[A-Za-z0-9_-]{32})$/
  );
  if (!match) return null;
  return { eventId: match[1].toLowerCase(), ipKey: match[2] };
}

export async function scheduleOwnerConfirmation(db, eventId, ipKey, nowMs = Date.now()) {
  if (!db) return { scheduled: false, reason: "db_unavailable" };
  const sid = pendingSid(eventId, ipKey);
  if (!sid) return { scheduled: false, reason: "invalid_identity" };
  const deadlineMs = nowMs + OWNER_CONFIRM_TIMEOUT_MS;

  try {
    await db
      .prepare(
        `INSERT OR REPLACE INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, NULL)`
      )
      .bind(sid, nowMs, deadlineMs)
      .run();
    return { scheduled: true, deadlineMs };
  } catch (error) {
    return {
      scheduled: false,
      reason: "schedule_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}

export async function getOwnerConfirmationState(db, eventId, nowMs = Date.now()) {
  if (!db) return null;
  const glob = pendingGlob(eventId);
  if (!glob) return null;

  try {
    const row = await db
      .prepare(
        `SELECT sid, issued_at_ms, expires_at_ms, consumed_at_ms
         FROM adaptive_live_capture_sessions
         WHERE sid GLOB ?
         ORDER BY issued_at_ms DESC
         LIMIT 1`
      )
      .bind(glob)
      .first();
    if (!row?.sid) return null;
    const parsed = parsePendingSid(row.sid);
    if (!parsed) return null;
    const deadlineMs = Number(row.expires_at_ms || 0);
    return {
      ...parsed,
      deadlineMs,
      expired: deadlineMs > 0 && nowMs >= deadlineMs,
      claimed: row.consumed_at_ms != null,
    };
  } catch {
    return null;
  }
}

export async function clearOwnerConfirmation(db, eventId) {
  if (!db) return false;
  const glob = pendingGlob(eventId);
  if (!glob) return false;
  try {
    await db
      .prepare(`DELETE FROM adaptive_live_capture_sessions WHERE sid GLOB ?`)
      .bind(glob)
      .run();
    return true;
  } catch {
    return false;
  }
}

async function clearAllOwnerConfirmations(db) {
  if (!db) return false;
  try {
    await db
      .prepare(`DELETE FROM adaptive_live_capture_sessions WHERE sid GLOB 'm22ownerpend_*'`)
      .run();
    return true;
  } catch {
    return false;
  }
}

async function deletePendingSid(db, sid) {
  try {
    await db
      .prepare(`DELETE FROM adaptive_live_capture_sessions WHERE sid = ?`)
      .bind(sid)
      .run();
  } catch {}
}

async function releasePendingSid(db, sid, retryAtMs) {
  try {
    await db
      .prepare(
        `UPDATE adaptive_live_capture_sessions
         SET consumed_at_ms = NULL, expires_at_ms = ?
         WHERE sid = ?`
      )
      .bind(retryAtMs, sid)
      .run();
  } catch {}
}

async function claimPendingSid(db, sid, nowMs) {
  try {
    const result = await db
      .prepare(
        `UPDATE adaptive_live_capture_sessions
         SET consumed_at_ms = ?
         WHERE sid = ? AND consumed_at_ms IS NULL`
      )
      .bind(nowMs, sid)
      .run();
    return Number(result?.meta?.changes || 0) > 0;
  } catch {
    return false;
  }
}

async function sendAutoNotMeTelegram(env, learning) {
  if (!env?.TELEGRAM_TOKEN || !env?.TELEGRAM_CHAT_ID) return;
  await sendTelegramWithKeyboard(
    env,
    `⏱️ AUTO NOT ME\nReason: no IT'S ME confirmation within 3 minutes\nIP: BLOCKED (exact IP only)\nOperatorLearning: ${learning?.learned ? "false_negative" : learning?.reason || "not-written"}\nRaw IP stored: false`,
    null
  );
}

export async function processOwnerLearningTimeouts(env, nowMs = Date.now()) {
  const db = env?.DB;
  if (!db) return { processed: 0, blocked: 0, reason: "db_unavailable" };

  // Switching to real/public traffic is a hard kill-switch for all outstanding
  // controlled-traffic timers. Old timers can never block after the mode is OFF.
  if (!ownerModeEnabled(env)) {
    await clearAllOwnerConfirmations(db);
    return { processed: 0, blocked: 0, reason: "owner_learning_off" };
  }

  let rows = [];
  try {
    const result = await db
      .prepare(
        `SELECT sid, expires_at_ms
         FROM adaptive_live_capture_sessions
         WHERE sid GLOB 'm22ownerpend_*'
           AND consumed_at_ms IS NULL
           AND expires_at_ms <= ?
         ORDER BY expires_at_ms ASC
         LIMIT 100`
      )
      .bind(nowMs)
      .all();
    rows = Array.isArray(result?.results) ? result.results : [];
  } catch {
    return { processed: 0, blocked: 0, reason: "query_failed" };
  }

  let processed = 0;
  let blocked = 0;

  for (const row of rows) {
    const parsed = parsePendingSid(row?.sid);
    if (!parsed) {
      await deletePendingSid(db, row?.sid);
      continue;
    }

    if (!(await claimPendingSid(db, row.sid, nowMs))) continue;
    processed += 1;

    // An explicit operator answer always wins if it was written before the
    // timeout worker claimed the row.
    const existing = await getAdaptiveFeedbackForEvent(db, parsed.eventId);
    if (existing) {
      await deletePendingSid(db, row.sid);
      continue;
    }

    const learning = await recordOperatorFalseNegative(db, parsed.eventId, nowMs);

    // Close the tiny race where IT'S ME was written between the first feedback
    // read and the false-negative insert attempt.
    if (!learning.learned && learning.reason === "feedback_already_exists") {
      const raced = await getAdaptiveFeedbackForEvent(db, parsed.eventId);
      if (raced?.label === "human_confirmed") {
        await deletePendingSid(db, row.sid);
        continue;
      }
    }

    const success = await setManualIpBlocked(
      db,
      parsed.ipKey,
      "owner_learning_timeout",
      nowMs
    );

    if (!success) {
      await releasePendingSid(db, row.sid, nowMs + 60_000);
      continue;
    }

    blocked += 1;
    await deletePendingSid(db, row.sid);
    await sendAutoNotMeTelegram(env, learning);
  }

  return { processed, blocked, reason: "ok" };
}
