import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const production = readFileSync(
  new URL("../src/v7-production-entry.js", import.meta.url),
  "utf8"
);

test("already-blocked exact IP is handled before the browser probe", () => {
  assert.match(production, /async function directExactIpBlock/);
  assert.match(production, /deriveManualIpKey/);
  assert.match(production, /isManualIpBlocked/);
  assert.match(production, /return redirectResponse\(request, env, "block"\) \|\| blockFallbackResponse\(\)/);
  assert.match(production, /const blocked = await directExactIpBlock\(request, env\)/);
  assert.match(production, /if \(blocked\) return blocked/);
});

test("blocked redirect is silent and has no visible redirecting text", () => {
  assert.match(production, /new Response\(null, \{/);
  assert.doesNotMatch(production, /Redirecting/i);
  assert.doesNotMatch(production, /Please wait/i);
});

test("production owns one final Telegram verdict and suppresses lower duplicate", () => {
  assert.match(production, /TELEGRAM_TOKEN: undefined/);
  assert.match(production, /TELEGRAM_CHAT_ID: undefined/);
  assert.match(production, /sendFinalTelegram/);
  assert.match(production, /buildTelegramDecisionMessage/);
});

test("final Telegram button is direct exact-IP HMAC and browser independent", () => {
  assert.match(production, /buildTelegramIpKeyCallbackKeyboard/);
  assert.match(production, /deriveManualIpKey\(env\.CHALLENGE_SECRET, clientIp\(request\)\)/);
  assert.match(production, /manual_ip_control_ready: telegram\.keyboardReady/);
  assert.match(production, /v7_telegram_buttons_direct_exact_ip_hmac: true/);
  assert.match(production, /v7_telegram_buttons_browser_independent: true/);
  assert.doesNotMatch(production, /rememberEventIpKey/);
  assert.doesNotMatch(production, /buildTelegramCallbackKeyboard/);
});

test("webhook self-healing is not used as a condition for attaching the button", () => {
  const keyboardIndex = production.indexOf("const keyboard = await buildTelegramIpKeyCallbackKeyboard");
  const webhookIndex = production.indexOf("const webhook = await ensureTelegramWebhook");
  assert.ok(keyboardIndex >= 0);
  assert.ok(webhookIndex > keyboardIndex);
  assert.doesNotMatch(production, /if \(webhookConfigured\)[\s\S]{0,300}buildTelegramIpKeyCallbackKeyboard/);
});
