import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deriveManualIpKey } from "../src/adaptive/manual-ip-block.js";
import {
  buildTelegramOwnerLearningKeyboard,
  parseTelegramIpCallback,
} from "../src/adaptive/telegram-callback.js";
import { ownerLearningEnabled } from "../src/adaptive/owner-learning.js";

const production = readFileSync(
  new URL("../src/v7-production-entry.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);
const ownerHelper = readFileSync(
  new URL("../src/adaptive/owner-learning.js", import.meta.url),
  "utf8"
);

test("OWNER_LEARNING_MODE is explicit true-only and defaults false", () => {
  assert.equal(ownerLearningEnabled({}), false);
  assert.equal(ownerLearningEnabled({ OWNER_LEARNING_MODE: "false" }), false);
  assert.equal(ownerLearningEnabled({ OWNER_LEARNING_MODE: "true" }), true);
  assert.equal(ownerLearningEnabled({ OWNER_LEARNING_MODE: "TRUE" }), true);
  assert.match(wrangler, /"OWNER_LEARNING_MODE"\s*:\s*"false"/);
});

test("owner HUMAN_PASS keyboard is English and signed without raw IP", async () => {
  const secret = "owner-learning-secret";
  const eventId = "12345678-abcd-4444-8888-123456789abc";
  const rawIp = "203.0.113.99";
  const ipKey = await deriveManualIpKey(secret, rawIp);
  const keyboard = await buildTelegramOwnerLearningKeyboard(secret, eventId, ipKey);

  assert.equal(keyboard.inline_keyboard[0][0].text, "✅ IT'S ME");
  assert.equal(keyboard.inline_keyboard[0][1].text, "❌ NOT ME");
  assert.doesNotMatch(JSON.stringify(keyboard), /203\.0\.113\.99/);

  const yes = await parseTelegramIpCallback(
    secret,
    keyboard.inline_keyboard[0][0].callback_data
  );
  const no = await parseTelegramIpCallback(
    secret,
    keyboard.inline_keyboard[0][1].callback_data
  );
  assert.equal(yes.action, "owner_yes");
  assert.equal(no.action, "owner_no");
  assert.equal(yes.ipKey, ipKey);
  assert.equal(no.ipKey, ipKey);
});

test("owner mode learns only after explicit click and only on HUMAN_PASS UI", () => {
  assert.match(production, /ownerLearningEnabled\(env\) && isHumanPassVerdict\(monitorVerdict\)/);
  assert.match(production, /buildTelegramOwnerLearningKeyboard/);
  assert.match(production, /OwnerLearning: HUMAN_PASS confirmation — IT'S ME \/ NOT ME/);
  assert.match(production, /owner_learning_requires_click: true/);
  assert.doesNotMatch(production, /recordOwnerHumanConfirmed\(/);
});

test("IT'S ME writes human_confirmed while public traffic stays outside training", () => {
  assert.match(ownerHelper, /label: "human_confirmed"/);
  assert.match(ownerHelper, /confidence: 100/);
  assert.match(ownerHelper, /trainingEligible: context\.datasetEligible === true/);
  assert.match(ownerHelper, /context\.v63Decision !== "allow"/);
});
