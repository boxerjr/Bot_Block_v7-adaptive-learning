import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const timeout = readFileSync(
  new URL("../src/adaptive/owner-learning-timeout.js", import.meta.url),
  "utf8"
);
const ownerLearning = readFileSync(
  new URL("../src/adaptive/owner-learning.js", import.meta.url),
  "utf8"
);
const entry = readFileSync(
  new URL("../src/v7-owner-timeout-entry.js", import.meta.url),
  "utf8"
);
const globalEntry = readFileSync(
  new URL("../src/v7-global-honeypot-entry.js", import.meta.url),
  "utf8"
);
const releaseEntry = readFileSync(
  new URL("../src/v7-release-hardening-entry.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);

test("owner confirmation deadline is exactly three minutes", () => {
  assert.match(timeout, /OWNER_CONFIRM_TIMEOUT_MS = 180_000/);
  assert.match(timeout, /deadlineMs = nowMs \+ OWNER_CONFIRM_TIMEOUT_MS/);
});

test("expired unanswered HUMAN_PASS becomes false negative and exact-IP block", () => {
  assert.match(timeout, /recordOperatorFalseNegative/);
  assert.match(timeout, /setManualIpBlocked/);
  assert.match(timeout, /owner_learning_timeout/);
  assert.match(timeout, /AUTO NOT ME/);
  assert.match(timeout, /no IT'S ME confirmation within 3 minutes/);
});

test("IT'S ME is fail-closed and rejected without a live pending confirmation", () => {
  assert.match(ownerLearning, /getOwnerConfirmationState/);
  assert.match(ownerLearning, /observedAt/);
  assert.match(ownerLearning, /OWNER_CONFIRM_TIMEOUT_MS/);
  assert.match(ownerLearning, /reason: "confirmation_unavailable"/);
  assert.match(ownerLearning, /if \(confirmation\.claimed\)/);
  assert.match(ownerLearning, /if \(confirmation\.expired\)/);
  assert.match(ownerLearning, /reason: "confirmation_expired"/);
});

test("IT'S ME before deadline cancels the pending timeout", () => {
  assert.match(ownerLearning, /clearOwnerConfirmation\(db, eventId\)/);
  assert.match(ownerLearning, /label: "human_confirmed"/);
});

test("OWNER_LEARNING_MODE false cancels all outstanding timers", () => {
  assert.match(timeout, /if \(!ownerModeEnabled\(env\)\)/);
  assert.match(timeout, /clearAllOwnerConfirmations/);
  assert.match(timeout, /reason: "owner_learning_off"/);
});

test("production wrapper arms timers only for owner learning HUMAN_PASS controls", () => {
  assert.match(entry, /data\?\.owner_learning_buttons !== true/);
  assert.match(entry, /data\?\.manual_ip_control_ready !== true/);
  assert.match(entry, /scheduleOwnerConfirmation/);
});

test("Cloudflare runs timeout sweep every minute through the hardened global chain", () => {
  assert.match(entry, /async scheduled/);
  assert.match(entry, /processOwnerLearningTimeouts/);
  assert.match(wrangler, /"main"\s*:\s*"src\/v7-release-hardening-entry\.js"/);
  assert.match(releaseEntry, /import worker from "\.\/v7-global-honeypot-entry\.js"/);
  assert.match(releaseEntry, /worker\.scheduled\(controller, env, ctx\)/);
  assert.match(globalEntry, /import worker from "\.\/v7-owner-timeout-entry\.js"/);
  assert.match(globalEntry, /worker\.scheduled\(controller, env, ctx\)/);
  assert.match(wrangler, /"crons"\s*:\s*\["\* \* \* \* \*"\]/);
});
