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

test("final Telegram control is event-bound for learning with direct exact-IP fallback", () => {
  assert.match(production, /rememberEventIpKey/);
  assert.match(production, /buildTelegramCallbackKeyboard/);
  assert.match(production, /buildTelegramIpKeyCallbackKeyboard/);
  assert.match(production, /deriveManualIpKey\(env\.CHALLENGE_SECRET, clientIp\(request\)\)/);
  assert.match(production, /manual_ip_control_ready: telegram\.keyboardReady/);
  assert.match(production, /v7_telegram_buttons_browser_independent: true/);
  assert.match(production, /operator feedback learning active/);
});

test("webhook self-healing is not used as a condition for attaching either keyboard", () => {
  const eventKeyboardIndex = production.indexOf("keyboard = await buildTelegramCallbackKeyboard");
  const fallbackKeyboardIndex = production.indexOf("keyboard = await buildTelegramIpKeyCallbackKeyboard");
  const webhookIndex = production.indexOf("const webhook = await ensureTelegramWebhook");
  assert.ok(eventKeyboardIndex >= 0);
  assert.ok(fallbackKeyboardIndex > eventKeyboardIndex);
  assert.ok(webhookIndex > fallbackKeyboardIndex);
  assert.doesNotMatch(production, /if \(webhookConfigured\)[\s\S]{0,300}buildTelegram/);
});
