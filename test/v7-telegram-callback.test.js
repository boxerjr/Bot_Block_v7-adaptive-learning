import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  buildTelegramCallbackKeyboard,
  parseTelegramIpCallback,
} from "../src/adaptive/telegram-callback.js";

const operational = readFileSync(
  new URL("../src/m22-operational-monitor-entry.js", import.meta.url),
  "utf8"
);

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

test("tampered callback is rejected", async () => {
  const eventId = "881e7c48-1111-4222-8333-123456789abc";
  const keyboard = await buildTelegramCallbackKeyboard("secret-value", eventId, "unblocked");
  const data = keyboard.inline_keyboard[0][0].callback_data;
  const tampered = data.slice(0, -1) + (data.endsWith("A") ? "B" : "A");
  assert.equal(await parseTelegramIpCallback("secret-value", tampered), null);
});

test("operational worker exposes Telegram webhook and no-browser callback flags", () => {
  assert.match(operational, /\/_telegram\/webhook/);
  assert.match(operational, /handleTelegramCallbackWebhook/);
  assert.match(operational, /ensureTelegramWebhook/);
  assert.match(operational, /manual_ip_callback_opens_browser: false/);
  assert.match(operational, /m22_telegram_callback_opens_browser: false/);
});
