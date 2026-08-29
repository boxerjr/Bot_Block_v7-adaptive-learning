import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  buildManualIpKeyboard,
  deriveManualIpKey,
  issueManualIpActionToken,
  verifyManualIpActionToken,
} from "../src/adaptive/manual-ip-block.js";

const operational = readFileSync(
  new URL("../src/m22-operational-monitor-entry.js", import.meta.url),
  "utf8"
);
const helper = readFileSync(
  new URL("../src/adaptive/manual-ip-block.js", import.meta.url),
  "utf8"
);

test("exact IP manual block key is deterministic, keyed, and does not expose raw IP", async () => {
  const ip = "203.0.113.44";
  const a = await deriveManualIpKey("manual-secret", ip);
  const b = await deriveManualIpKey("manual-secret", ip);
  const c = await deriveManualIpKey("manual-secret", "203.0.113.45");

  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^m22ip_[A-Za-z0-9_-]{32}$/);
  assert.doesNotMatch(a, /203\.0\.113\.44/);
});

test("manual IP action token is signed and action-scoped", async () => {
  const token = await issueManualIpActionToken("manual-secret", {
    eventId: "11111111-2222-3333-4444-555555555555",
    action: "block",
  });
  const payload = await verifyManualIpActionToken("manual-secret", token);
  assert.equal(payload?.type, "m22_manual_ip_action");
  assert.equal(payload?.action, "block");
  assert.equal(payload?.event_id, "11111111-2222-3333-4444-555555555555");

  const wrongSecret = await verifyManualIpActionToken("wrong-secret", token);
  assert.equal(wrongSecret, null);
});

test("legacy Telegram URL keyboard remains available only for old messages", async () => {
  const keyboard = await buildManualIpKeyboard(
    "https://test.example/_shadow/v7-monitor-submit",
    "manual-secret",
    "11111111-2222-3333-4444-555555555555"
  );

  const serialized = JSON.stringify(keyboard);
  assert.match(serialized, /BLOCK IP/);
  assert.match(serialized, /UNBLOCK IP/);
  assert.match(serialized, /_telegram\/ip-action/);
  assert.doesNotMatch(serialized, /203\.0\.113\./);
});

test("operational monitor enforces explicit exact-IP blocks while AI remains non-enforcing", () => {
  assert.match(operational, /deriveManualIpKey/);
  assert.match(operational, /isManualIpBlocked/);
  assert.match(operational, /status: 404/);
  assert.match(operational, /manual_ip_block_enforcing: true/);
  assert.match(operational, /ai_bot_enforcing: false/);
  assert.match(operational, /manual_ip_raw_stored: false/);
  assert.match(operational, /_telegram\/webhook/);
  assert.match(operational, /Telegram callback BLOCK \/ UNBLOCK/);
  assert.match(operational, /manual_ip_callback_opens_browser: false/);
});

test("country policy precedes human bot monitor verdict and enforces 404", () => {
  assert.match(operational, /countryAllowed/);
  assert.match(operational, /BLOCK_BY_COUNTRY/);
  assert.match(operational, /blocked_country/);
  assert.match(operational, /country_policy_enforcing: true/);
  assert.match(operational, /m22_country_policy_precedes_monitor_verdict: true/);
  assert.match(operational, /m22_country_policy_block_status: 404/);
});

test("manual block persistence stores HMAC keys, never a raw-ip column", () => {
  assert.match(helper, /m22-exact-ip:/);
  assert.match(helper, /m22blk_/);
  assert.match(helper, /adaptive_live_capture_sessions/);
  assert.doesNotMatch(helper, /raw_ip\s*[,) ]/i);
});
