function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function b64urlToBytes(value) {
  let input = String(value || "").replaceAll("-", "+").replaceAll("_", "/");
  while (input.length % 4) input += "=";
  const binary = atob(input);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) output[i] = binary.charCodeAt(i);
  return output;
}

function textToB64url(text) {
  return bytesToB64url(new TextEncoder().encode(String(text)));
}

function b64urlToText(value) {
  return new TextDecoder().decode(b64urlToBytes(value));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signBytes(secret, value) {
  const key = await hmacKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(value))
  );
  return new Uint8Array(signature);
}

async function signText(secret, body) {
  return bytesToB64url(await signBytes(secret, body));
}

const EVENT_MAP_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const ACTION_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const BLOCK_TTL_MS = 10 * 365 * 24 * 60 * 60 * 1000;

function eventPrefix(eventId) {
  return `m22ip_event_${String(eventId || "")}_`;
}

function blockSid(ipKey) {
  return `m22blk_${String(ipKey || "")}`;
}

export async function deriveManualIpKey(secret, ip) {
  if (!secret) return null;
  const digest = await signBytes(secret, `m22-exact-ip:${String(ip || "unknown")}`);
  return `m22ip_${bytesToB64url(digest).slice(0, 32)}`;
}

export async function rememberEventIpKey(db, eventId, ipKey, nowMs = Date.now()) {
  if (!db || !eventId || !ipKey) return false;
  const sid = `${eventPrefix(eventId)}${ipKey}`;
  try {
    await db
      .prepare(
        `INSERT OR REPLACE INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, ?)`
      )
      .bind(sid, nowMs, nowMs + EVENT_MAP_TTL_MS, nowMs)
      .run();
    return true;
  } catch {
    return false;
  }
}

export async function getEventIpKey(db, eventId, nowMs = Date.now()) {
  if (!db || !eventId) return null;
  const prefix = eventPrefix(eventId);
  try {
    const row = await db
      .prepare(
        `SELECT sid
         FROM adaptive_live_capture_sessions
         WHERE sid LIKE ?
           AND expires_at_ms > ?
         ORDER BY issued_at_ms DESC
         LIMIT 1`
      )
      .bind(`${prefix}%`, nowMs)
      .first();
    const sid = String(row?.sid || "");
    return sid.startsWith(prefix) ? sid.slice(prefix.length) : null;
  } catch {
    return null;
  }
}

export async function isManualIpBlocked(db, ipKey, nowMs = Date.now()) {
  if (!db || !ipKey) return false;
  try {
    const row = await db
      .prepare(
        `SELECT sid
         FROM adaptive_live_capture_sessions
         WHERE sid = ?
           AND expires_at_ms > ?
         LIMIT 1`
      )
      .bind(blockSid(ipKey), nowMs)
      .first();
    return !!row?.sid;
  } catch {
    return false;
  }
}

export async function setManualIpBlocked(db, ipKey, eventId, nowMs = Date.now()) {
  if (!db || !ipKey) return false;
  try {
    await db
      .prepare(
        `INSERT OR REPLACE INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, ?)`
      )
      .bind(blockSid(ipKey), nowMs, nowMs + BLOCK_TTL_MS, nowMs)
      .run();
    return true;
  } catch {
    return false;
  }
}

export async function clearManualIpBlocked(db, ipKey) {
  if (!db || !ipKey) return false;
  try {
    await db
      .prepare(`DELETE FROM adaptive_live_capture_sessions WHERE sid = ?`)
      .bind(blockSid(ipKey))
      .run();
    return true;
  } catch {
    return false;
  }
}

export async function issueManualIpActionToken(secret, {
  eventId,
  action,
  ttlMs = ACTION_TTL_MS,
} = {}) {
  if (!secret || !eventId || !["block", "unblock"].includes(action)) return null;
  const now = Date.now();
  const payload = {
    type: "m22_manual_ip_action",
    event_id: String(eventId),
    action,
    iat: now,
    exp: now + Math.max(60_000, Math.min(ACTION_TTL_MS, Number(ttlMs) || ACTION_TTL_MS)),
  };
  const body = textToB64url(JSON.stringify(payload));
  return `${body}.${await signText(secret, body)}`;
}

export async function verifyManualIpActionToken(secret, token) {
  try {
    if (!secret) return null;
    const [body, signature, extra] = String(token || "").split(".");
    if (!body || !signature || extra) return null;
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      b64urlToBytes(signature),
      new TextEncoder().encode(body)
    );
    if (!valid) return null;
    const payload = JSON.parse(b64urlToText(body));
    if (payload?.type !== "m22_manual_ip_action") return null;
    if (!payload.event_id || !["block", "unblock"].includes(payload.action)) return null;
    if (!Number.isFinite(Number(payload.exp)) || Date.now() >= Number(payload.exp)) return null;
    return payload;
  } catch {
    return null;
  }
}

export async function buildManualIpKeyboard(requestUrl, secret, eventId) {
  const blockToken = await issueManualIpActionToken(secret, { eventId, action: "block" });
  const unblockToken = await issueManualIpActionToken(secret, { eventId, action: "unblock" });
  if (!blockToken || !unblockToken) return null;

  const blockUrl = new URL("/_telegram/ip-action", requestUrl);
  blockUrl.searchParams.set("token", blockToken);
  const unblockUrl = new URL("/_telegram/ip-action", requestUrl);
  unblockUrl.searchParams.set("token", unblockToken);

  return {
    inline_keyboard: [
      [
        { text: "🚫 BLOCK IP", url: blockUrl.toString() },
        { text: "🔓 UNBLOCK IP", url: unblockUrl.toString() },
      ],
    ],
  };
}

export async function sendTelegramWithKeyboard(env, text, replyMarkup) {
  const token = env?.TELEGRAM_TOKEN;
  const chatId = env?.TELEGRAM_CHAT_ID;
  if (!token || !chatId || !text) return { sent: false, reason: "telegram_not_bound" };

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: String(chatId),
        text: String(text).slice(0, 3900),
        disable_web_page_preview: true,
        ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
      }),
    });
    return { sent: response.ok, status: response.status };
  } catch (error) {
    return {
      sent: false,
      reason: "telegram_fetch_error",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}
