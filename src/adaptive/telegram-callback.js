import {
  clearManualIpBlocked,
  getEventIpKey,
  setManualIpBlocked,
} from "./manual-ip-block.js";
import { clearMonitorRateLimitForIpKey } from "./monitor-rate-limit.js";

function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

async function hmacBytes(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(value))
  );
  return new Uint8Array(sig);
}

async function hmacShort(secret, value, length = 12) {
  return bytesToB64url(await hmacBytes(secret, value)).slice(0, length);
}

function safeEqual(a, b) {
  const aa = String(a || "");
  const bb = String(b || "");
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return diff === 0;
}

function validIpKey(ipKey) {
  return /^m22ip_[A-Za-z0-9_-]{32}$/.test(String(ipKey || ""));
}

async function telegramApi(env, method, payload) {
  if (!env?.TELEGRAM_TOKEN) return { ok: false, reason: "telegram_not_bound" };
  try {
    const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload || {}),
    });
    let body = null;
    try { body = await response.json(); } catch {}
    return { ok: response.ok && body?.ok !== false, status: response.status, body };
  } catch (error) {
    return { ok: false, reason: "telegram_fetch_error", error: String(error?.message || error).slice(0, 120) };
  }
}

async function callbackData(secret, eventId, action) {
  const code = action === "block" ? "b" : "u";
  const event = String(eventId || "");
  const sig = await hmacShort(secret, `m22-callback:${code}:${event}`, 12);
  return `m22:${code}:${event}:${sig}`;
}

async function ipKeyCallbackData(secret, ipKey, action) {
  const code = action === "block" ? "b" : "u";
  const key = String(ipKey || "");
  if (!validIpKey(key)) return null;
  const keyPart = key.slice("m22ip_".length);
  const sig = await hmacShort(secret, `m22-ipkey-callback:${code}:${key}`, 10);
  return `m22k:${code}:${keyPart}:${sig}`;
}

export async function parseTelegramIpCallback(secret, data) {
  const value = String(data || "");
  if (!secret) return null;

  const direct = value.match(/^m22k:([bu]):([A-Za-z0-9_-]{32}):([A-Za-z0-9_-]{10})$/);
  if (direct) {
    const [, code, keyPart, supplied] = direct;
    const ipKey = `m22ip_${keyPart}`;
    const expected = await hmacShort(secret, `m22-ipkey-callback:${code}:${ipKey}`, 10);
    if (!safeEqual(supplied, expected)) return null;
    return { action: code === "b" ? "block" : "unblock", ipKey };
  }

  const legacy = value.match(/^m22:([bu]):([0-9a-fA-F-]{36}):([A-Za-z0-9_-]{12})$/);
  if (!legacy) return null;
  const [, code, eventId, supplied] = legacy;
  const expected = await hmacShort(secret, `m22-callback:${code}:${eventId}`, 12);
  if (!safeEqual(supplied, expected)) return null;
  return { action: code === "b" ? "block" : "unblock", eventId };
}

export async function buildTelegramCallbackKeyboard(secret, eventId, state = "unblocked") {
  if (!secret || !eventId) return null;
  if (state === "blocked") {
    return {
      inline_keyboard: [[
        { text: "🔓 UNBLOCK IP", callback_data: await callbackData(secret, eventId, "unblock") },
      ]],
    };
  }
  return {
    inline_keyboard: [[
      { text: "🚫 BLOCK IP", callback_data: await callbackData(secret, eventId, "block") },
    ]],
  };
}

export async function buildTelegramIpKeyCallbackKeyboard(secret, ipKey, state = "blocked") {
  if (!secret || !validIpKey(ipKey)) return null;
  if (state === "blocked") {
    return {
      inline_keyboard: [[
        { text: "🔓 UNBLOCK IP", callback_data: await ipKeyCallbackData(secret, ipKey, "unblock") },
      ]],
    };
  }
  return {
    inline_keyboard: [[
      { text: "🚫 BLOCK IP", callback_data: await ipKeyCallbackData(secret, ipKey, "block") },
    ]],
  };
}

async function webhookSecret(secret) {
  return `m22_${await hmacShort(secret, "m22-telegram-webhook-secret", 32)}`;
}

async function webhookOriginId(secret, origin) {
  return await hmacShort(secret, `m22-webhook-origin:${origin}`, 18);
}

async function webhookSecretId(secret) {
  return await hmacShort(secret, "m22-webhook-secret-installed", 18);
}

async function readMarker(db, sid, nowMs) {
  try {
    const row = await db
      .prepare(`SELECT expires_at_ms FROM adaptive_live_capture_sessions WHERE sid = ? LIMIT 1`)
      .bind(sid)
      .first();
    return !!row && Number(row.expires_at_ms) > nowMs;
  } catch {
    return false;
  }
}

async function writeMarker(db, sid, nowMs, ttlMs) {
  try {
    await db
      .prepare(
        `INSERT OR REPLACE INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, ?)`
      )
      .bind(sid, nowMs, nowMs + ttlMs, nowMs)
      .run();
    return true;
  } catch {
    return false;
  }
}

async function markWebhookVerified(db, activeSid, secretSid, nowMs) {
  try {
    await db
      .prepare(`DELETE FROM adaptive_live_capture_sessions WHERE sid GLOB 'm22tgwh_active_*' AND sid <> ?`)
      .bind(activeSid)
      .run();
  } catch {}
  await writeMarker(db, activeSid, nowMs, 60_000);
  await writeMarker(db, secretSid, nowMs, 86_400_000);
}

/**
 * Verify that Telegram is actually pointing callback_query updates at the
 * current V7 origin. D1 is only a short verification cache; it is never treated
 * as proof after another deployment/origin may have replaced the bot webhook.
 */
export async function ensureTelegramWebhook(env, requestUrl, nowMs = Date.now()) {
  if (!env?.DB || !env?.CHALLENGE_SECRET || !env?.TELEGRAM_TOKEN || !requestUrl) {
    return { ready: false, configured: false, verified: false, reason: "missing_binding" };
  }

  const origin = new URL(requestUrl).origin;
  const webhookUrl = new URL("/_telegram/webhook", origin).toString();
  const activeSid = `m22tgwh_active_${await webhookOriginId(env.CHALLENGE_SECRET, origin)}`;
  const secretSid = `m22tgwh_secret_${await webhookSecretId(env.CHALLENGE_SECRET)}`;

  // Fast path: only trust a very recent verification owned by this exact origin.
  if (await readMarker(env.DB, activeSid, nowMs)) {
    return {
      ready: true,
      configured: true,
      verified: true,
      cached: true,
      origin,
      webhook_url_matches: true,
    };
  }

  const info = await telegramApi(env, "getWebhookInfo", {});
  const currentUrl = String(info?.body?.result?.url || "");
  const urlMatches = info.ok && currentUrl === webhookUrl;
  const currentSecretInstalled = await readMarker(env.DB, secretSid, nowMs);

  // If Telegram reports the correct URL and this CHALLENGE_SECRET previously
  // installed the webhook secret token, refresh the short verification cache.
  if (urlMatches && currentSecretInstalled) {
    await markWebhookVerified(env.DB, activeSid, secretSid, nowMs);
    return {
      ready: true,
      configured: true,
      verified: true,
      cached: false,
      repaired: false,
      origin,
      webhook_url_matches: true,
      pending_update_count: Number(info?.body?.result?.pending_update_count || 0),
    };
  }

  // URL mismatch, stale external overwrite, or a new CHALLENGE_SECRET: repair it.
  const secretToken = await webhookSecret(env.CHALLENGE_SECRET);
  const configured = await telegramApi(env, "setWebhook", {
    url: webhookUrl,
    secret_token: secretToken,
    allowed_updates: ["callback_query"],
    drop_pending_updates: false,
  });
  if (!configured.ok) {
    return {
      ready: true,
      configured: false,
      verified: false,
      repaired: false,
      origin,
      reason: "set_webhook_failed",
      status: configured.status || null,
    };
  }

  const verify = await telegramApi(env, "getWebhookInfo", {});
  const verifiedUrl = String(verify?.body?.result?.url || "");
  const verified = verify.ok && verifiedUrl === webhookUrl;
  if (!verified) {
    return {
      ready: true,
      configured: false,
      verified: false,
      repaired: true,
      origin,
      reason: "webhook_verification_failed",
      status: verify.status || null,
    };
  }

  await markWebhookVerified(env.DB, activeSid, secretSid, nowMs);
  return {
    ready: true,
    configured: true,
    verified: true,
    cached: false,
    repaired: true,
    origin,
    webhook_url_matches: true,
    pending_update_count: Number(verify?.body?.result?.pending_update_count || 0),
  };
}

async function answerCallback(env, callbackId, text, showAlert = false) {
  if (!callbackId) return;
  await telegramApi(env, "answerCallbackQuery", {
    callback_query_id: callbackId,
    text: String(text).slice(0, 180),
    show_alert: !!showAlert,
  });
}

export async function handleTelegramCallbackWebhook(request, env) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (!env?.DB || !env?.CHALLENGE_SECRET || !env?.TELEGRAM_TOKEN || !env?.TELEGRAM_CHAT_ID) {
    return new Response("Unavailable", { status: 503 });
  }

  const expectedSecret = await webhookSecret(env.CHALLENGE_SECRET);
  const suppliedSecret = request.headers.get("x-telegram-bot-api-secret-token") || "";
  if (!safeEqual(suppliedSecret, expectedSecret)) {
    return new Response("Unauthorized", { status: 401 });
  }

  let update;
  try { update = await request.json(); } catch { return new Response("Bad Request", { status: 400 }); }
  const cb = update?.callback_query;
  if (!cb) return new Response("OK", { status: 200 });

  const chatId = String(cb?.message?.chat?.id ?? "");
  if (chatId !== String(env.TELEGRAM_CHAT_ID)) {
    await answerCallback(env, cb.id, "Unauthorized chat");
    return new Response("OK", { status: 200 });
  }

  const parsed = await parseTelegramIpCallback(env.CHALLENGE_SECRET, cb.data || "");
  if (!parsed) {
    await answerCallback(env, cb.id, "Invalid or expired action", true);
    return new Response("OK", { status: 200 });
  }

  const ipKey = parsed.ipKey || await getEventIpKey(env.DB, parsed.eventId);
  if (!ipKey) {
    await answerCallback(env, cb.id, "Exact-IP mapping is unavailable", true);
    return new Response("OK", { status: 200 });
  }

  let success = false;
  let countersCleared = true;
  if (parsed.action === "block") {
    success = await setManualIpBlocked(env.DB, ipKey, parsed.eventId || "telegram_direct");
  } else {
    success = await clearManualIpBlocked(env.DB, ipKey);
    if (success) {
      countersCleared = await clearMonitorRateLimitForIpKey(env.DB, ipKey);
    }
  }

  if (!success || !countersCleared) {
    await answerCallback(env, cb.id, "IP action failed — try again", true);
    return new Response("OK", { status: 200 });
  }

  const blocked = parsed.action === "block";
  const confirmation = blocked
    ? "✅ IP BLOCKED\nExact IP only\nRaw IP stored: false"
    : "✅ IP UNBLOCKED\nExact IP only\nRate-limit counters reset: true\nRaw IP stored: false";

  await answerCallback(
    env,
    cb.id,
    blocked ? "✅ IP BLOCKED — Exact IP only" : "✅ IP UNBLOCKED — access restored",
    true
  );

  await telegramApi(env, "sendMessage", {
    chat_id: String(env.TELEGRAM_CHAT_ID),
    text: confirmation,
    disable_web_page_preview: true,
  });

  const nextKeyboard = parsed.ipKey
    ? await buildTelegramIpKeyCallbackKeyboard(
        env.CHALLENGE_SECRET,
        ipKey,
        blocked ? "blocked" : "unblocked"
      )
    : await buildTelegramCallbackKeyboard(
        env.CHALLENGE_SECRET,
        parsed.eventId,
        blocked ? "blocked" : "unblocked"
      );

  if (cb?.message?.message_id && nextKeyboard) {
    await telegramApi(env, "editMessageReplyMarkup", {
      chat_id: String(env.TELEGRAM_CHAT_ID),
      message_id: cb.message.message_id,
      reply_markup: nextKeyboard,
    });
  }

  return new Response("OK", { status: 200 });
}
