import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  buildTelegramCallbackKeyboard,
  buildTelegramIpKeyCallbackKeyboard,
  ensureTelegramWebhook,
  parseTelegramIpCallback,
} from "../src/adaptive/telegram-callback.js";

const operational = readFileSync(
  new URL("../src/m22-operational-monitor-entry.js", import.meta.url),
  "utf8"
);
const callbackSource = readFileSync(
  new URL("../src/adaptive/telegram-callback.js", import.meta.url),
  "utf8"
);

function fakeDb() {
  const rows = new Map();
  return {
    prepare(sql) {
      const statement = String(sql);
      return {
        bind(...args) {
          return {
            async first() {
              if (statement.includes("WHERE sid = ?")) {
                const row = rows.get(String(args[0] || ""));
                return row ? { expires_at_ms: row.expires_at_ms } : null;
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
              if (statement.includes("DELETE FROM adaptive_live_capture_sessions") && statement.includes("m22tgwh_active_")) {
                const keep = String(args[0] || "");
                for (const sid of [...rows.keys()]) {
                  if (sid.startsWith("m22tgwh_active_") && sid !== keep) rows.delete(sid);
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

test("manual IP keyboard uses Telegram callback_data and never a URL", async () => {
  const eventId = "881e7c48-1111-4222-8333-123456789abc";
  const keyboard = await buildTelegramCallbackKeyboard("secret-value", eventId, "unblocked");
  const button = keyboard.inline_keyboard[0][0];

  assert.equal(button.text, "🚫 BLOCK IP");
  assert.equal(typeof button.callback_data, "string");
  assert.ok(button.callback_data.length <= 64);
  assert.equal("url" in button, false);

  const parsed = await parseTelegramIpCallback("secret-value", button.callback_data);
  assert.deepEqual(parsed, { action: "block", eventId });
});

test("blocked keyboard exposes only UNBLOCK callback and no browser URL", async () => {
  const eventId = "881e7c48-1111-4222-8333-123456789abc";
  const keyboard = await buildTelegramCallbackKeyboard("secret-value", eventId, "blocked");
  const button = keyboard.inline_keyboard[0][0];

  assert.equal(button.text, "🔓 UNBLOCK IP");
  assert.ok(button.callback_data.length <= 64);
  assert.equal("url" in button, false);

  const parsed = await parseTelegramIpCallback("secret-value", button.callback_data);
  assert.deepEqual(parsed, { action: "unblock", eventId });
});

test("rate-limit auto-block keyboard embeds only signed exact-IP HMAC and unblocks without event mapping", async () => {
  const ipKey = "m22ip_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
  const keyboard = await buildTelegramIpKeyCallbackKeyboard("secret-value", ipKey, "blocked");
  const button = keyboard.inline_keyboard[0][0];

  assert.equal(button.text, "🔓 UNBLOCK IP");
  assert.equal("url" in button, false);
  assert.ok(button.callback_data.length <= 64);
  assert.equal(button.callback_data.includes("203.0.113."), false);

  const parsed = await parseTelegramIpCallback("secret-value", button.callback_data);
  assert.deepEqual(parsed, { action: "unblock", ipKey });
});

test("tampered direct exact-IP callback is rejected", async () => {
  const ipKey = "m22ip_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
  const keyboard = await buildTelegramIpKeyCallbackKeyboard("secret-value", ipKey, "blocked");
  const data = keyboard.inline_keyboard[0][0].callback_data;
  const tampered = data.slice(0, -1) + (data.endsWith("A") ? "B" : "A");
  assert.equal(await parseTelegramIpCallback("secret-value", tampered), null);
});

test("tampered legacy callback is rejected", async () => {
  const eventId = "881e7c48-1111-4222-8333-123456789abc";
  const keyboard = await buildTelegramCallbackKeyboard("secret-value", eventId, "unblocked");
  const data = keyboard.inline_keyboard[0][0].callback_data;
  const tampered = data.slice(0, -1) + (data.endsWith("A") ? "B" : "A");
  assert.equal(await parseTelegramIpCallback("secret-value", tampered), null);
});

test("ensureTelegramWebhook repairs a stale webhook and verifies the current V7 origin", async () => {
  const originalFetch = globalThis.fetch;
  const db = fakeDb();
  const calls = [];
  let currentUrl = "https://old-preview.example/_telegram/webhook";

  globalThis.fetch = async (url, options = {}) => {
    const method = String(url).split("/").pop();
    calls.push(method);

    if (method === "getWebhookInfo") {
      return new Response(JSON.stringify({
        ok: true,
        result: { url: currentUrl, pending_update_count: 0 },
      }), { status: 200, headers: { "content-type": "application/json" } });
    }

    if (method === "setWebhook") {
      const body = JSON.parse(String(options.body || "{}"));
      currentUrl = body.url;
      assert.equal(currentUrl, "https://monitor.example/_telegram/webhook");
      assert.equal(body.allowed_updates.includes("callback_query"), true);
      assert.equal(typeof body.secret_token, "string");
      return new Response(JSON.stringify({ ok: true, result: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    throw new Error(`Unexpected Telegram method ${method}`);
  };

  try {
    const env = {
      DB: db,
      CHALLENGE_SECRET: "challenge-secret",
      TELEGRAM_TOKEN: "telegram-token",
    };

    const repaired = await ensureTelegramWebhook(
      env,
      "https://monitor.example/_shadow/v7-monitor-submit",
      1_800_000_000_000
    );
    assert.equal(repaired.configured, true);
    assert.equal(repaired.verified, true);
    assert.equal(repaired.repaired, true);
    assert.equal(repaired.webhook_url_matches, true);
    assert.deepEqual(calls, ["getWebhookInfo", "setWebhook", "getWebhookInfo"]);

    calls.length = 0;
    const cached = await ensureTelegramWebhook(
      env,
      "https://monitor.example/check",
      1_800_000_000_001
    );
    assert.equal(cached.configured, true);
    assert.equal(cached.verified, true);
    assert.equal(cached.cached, true);
    assert.deepEqual(calls, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("successful unblock resets rate-limit counters and shows Telegram alert", () => {
  assert.match(callbackSource, /clearMonitorRateLimitForIpKey/);
  assert.match(callbackSource, /Rate-limit counters reset: true/);
  assert.match(callbackSource, /show_alert: !!showAlert/);
  assert.match(callbackSource, /IP UNBLOCKED — access restored/);
});

test("webhook configuration is verified against Telegram instead of trusting a long D1 marker", () => {
  assert.match(callbackSource, /getWebhookInfo/);
  assert.match(callbackSource, /webhook_url_matches/);
  assert.match(callbackSource, /webhook_verification_failed/);
  assert.match(callbackSource, /m22tgwh_active_/);
});

test("operational worker exposes Telegram webhook and no-browser callback flags", () => {
  assert.match(operational, /\/_telegram\/webhook/);
  assert.match(operational, /handleTelegramCallbackWebhook/);
  assert.match(operational, /ensureTelegramWebhook/);
  assert.match(operational, /buildTelegramIpKeyCallbackKeyboard/);
  assert.match(operational, /m22_rate_limit_unblock_resets_counters: true/);
  assert.match(operational, /manual_ip_callback_opens_browser: false/);
  assert.match(operational, /m22_telegram_callback_opens_browser: false/);
});

test("Telegram callback identity tolerates harmless whitespace around configured chat ID", () => {
  assert.match(callbackSource, /normalizedTelegramChatId/);
  assert.match(callbackSource, /String\(value \?\? ""\)\.trim\(\)/);
  assert.match(callbackSource, /suppliedSecret = .*\.trim\(\)/);
});
