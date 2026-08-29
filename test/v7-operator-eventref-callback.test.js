import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  buildTelegramEventIpKeyCallbackKeyboard,
  parseTelegramIpCallback,
} from "../src/adaptive/telegram-callback.js";

const callbackSource = readFileSync(
  new URL("../src/adaptive/telegram-callback.js", import.meta.url),
  "utf8"
);

test("event-bound callback carries compact event reference and exact-IP HMAC within Telegram limit", async () => {
  const eventId = "ffc5304f-1234-4abc-8def-123456789abc";
  const ipKey = "m22ip_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
  const keyboard = await buildTelegramEventIpKeyCallbackKeyboard(
    "secret-value",
    eventId,
    ipKey,
    "unblocked"
  );
  const button = keyboard.inline_keyboard[0][0];

  assert.equal(button.text, "🚫 BLOCK IP");
  assert.ok(button.callback_data.length <= 64);
  assert.equal(button.callback_data.length, 63);
  assert.equal("url" in button, false);

  const parsed = await parseTelegramIpCallback("secret-value", button.callback_data);
  assert.deepEqual(parsed, {
    action: "block",
    ipKey,
    eventRef: "ffc5304f-1234",
  });
});

test("event-bound callback is signed and tampering is rejected", async () => {
  const keyboard = await buildTelegramEventIpKeyCallbackKeyboard(
    "secret-value",
    "ffc5304f-1234-4abc-8def-123456789abc",
    "m22ip_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
    "unblocked"
  );
  const data = keyboard.inline_keyboard[0][0].callback_data;
  const tampered = data.slice(0, -1) + (data.endsWith("A") ? "B" : "A");
  assert.equal(await parseTelegramIpCallback("secret-value", tampered), null);
});

test("event reference resolution rejects ambiguity and keeps exact-IP fallback", () => {
  assert.match(callbackSource, /WHERE event_id LIKE \?1/);
  assert.match(callbackSource, /LIMIT 2/);
  assert.match(callbackSource, /rows\.length !== 1/);
  assert.match(callbackSource, /eventId \|\| "telegram_direct"/);
});
