import {
  clearManualIpBlocked,
  getEventIpKey,
  setManualIpBlocked,
} from "./manual-ip-block.js";

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

export async function parseTelegramIpCallback(secret, data) {
  const value = String(data || "");
  const match = value.match(/^m22:([bu]):([0-9a-fA-F-]{36}):([A-Za-z0-9_-]{12})$/);
  if (!match || !secret) return null;
  const [, code, eventId, supplied] = match;
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

async function webhookSecret(secret) {
  return `m22_${await hmacShort(secret, "m22-telegram-webhook-secret", 32)}`;
}

async function markerSid(secret, origin) {
  return `m22tgwh_${await hmacShort(secret, `origin:${origin}`, 18)}`;
}

export async function ensureTelegramWebhook(env, requestUrl, nowMs = Date.now()) {
  if (!env?.DB || !env?.CHALLENGE_SECRET || !env?.TELEGRAM_TOKEN || !requestUrl) {
    return { ready: false, configured: false, reason: "missing_binding" };
  }

  const origin = new URL(requestUrl).origin;
  const sid = await markerSid(env.CHALLENGE_SECRET, origin);
  try {
    const existing = await env.DB
      .prepare(`SELECT expires_at_ms FROM adaptive_live_capture_sessions WHERE sid = ? LIMIT 1`)
      .bind(sid)
      .first();
    if (existing && Number(existing.expires_at_ms) > nowMs) {
      return { ready: true, configured: true, cached: true, origin };
    }
  } catch {}

  const webhookUrl = new URL("/_telegram/webhook", origin).toString();
  const secretToken = await webhookSecret(env.CHALLENGE_SECRET);
  const configured = await telegramApi(env, "setWebhook", {
    url: webhookUrl,
    secret_token: secretToken,
    allowed_updates: ["callback_query"],
    drop_pending_updates: false,
  });
  if (!configured.ok) {
    return { ready: true, configured: false, origin, status: configured.status || null };
  }

  try {
    await env.DB
      .prepare(
        `INSERT OR REPLACE INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, ?)`
      )
      .bind(sid, nowMs, nowMs + 86_400_000, nowMs)
      .run();
  } catch {}

  return { ready: true, configured: true, cached: false, origin };
}

async function answerCallback(env, callbackId, text) {
  if (!callbackId) return;
  await telegramApi(env, "answerCallbackQuery", {
    callback_query_id: callbackId,
    text: String(text).slice(0, 180),
    show_alert: false,
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
    await answerCallback(env, cb.id, "Invalid or expired action");
    return new Response("OK", { status: 200 });
  }

  const ipKey = await getEventIpKey(env.DB, parsed.eventId);
  if (!ipKey) {
    await answerCallback(env, cb.id, "Event IP mapping expired");
    return new Response("OK", { status: 200 });
  }

  const success = parsed.action === "block"
    ? await setManualIpBlocked(env.DB, ipKey, parsed.eventId)
    : await clearManualIpBlocked(env.DB, ipKey);

  if (!success) {
    await answerCallback(env, cb.id, "IP action failed");
    return new Response("OK", { status: 200 });
  }

  const blocked = parsed.action === "block";
  const confirmation = blocked
    ? "✅ IP BLOCKED\nExact IP only\nRaw IP stored: false"
    : "✅ IP UNBLOCKED\nExact IP only\nRaw IP stored: false";

  await answerCallback(env, cb.id, blocked ? "✅ IP BLOCKED — Exact IP only" : "✅ IP UNBLOCKED — Exact IP only");

  await telegramApi(env, "sendMessage", {
    chat_id: String(env.TELEGRAM_CHAT_ID),
    text: confirmation,
    disable_web_page_preview: true,
  });

  const nextKeyboard = await buildTelegramCallbackKeyboard(
    env.CHALLENGE_SECRET,
    parsed.eventId,
    blocked ? "blocked" : "unblocked"
  );

  if (cb?.message?.message_id) {
    await telegramApi(env, "editMessageReplyMarkup", {
      chat_id: String(env.TELEGRAM_CHAT_ID),
      message_id: cb.message.message_id,
      reply_markup: nextKeyboard,
    });
  }

  return new Response("OK", { status: 200 });
}
