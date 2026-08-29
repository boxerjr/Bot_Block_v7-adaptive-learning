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

test("IT'S ME is rejected after the three-minute deadline", () => {
  assert.match(ownerLearning, /getOwnerConfirmationState/);
  assert.match(ownerLearning, /confirmation\?\.expired/);
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

test("Cloudflare runs the timeout sweep every minute", () => {
  assert.match(entry, /async scheduled/);
  assert.match(entry, /processOwnerLearningTimeouts/);
  assert.match(wrangler, /"main": "src\/v7-owner-timeout-entry\.js"/);
  assert.match(wrangler, /"crons": \["\* \* \* \* \*"\]/);
});
