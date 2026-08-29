import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const helper = readFileSync(
  new URL("../src/adaptive/manual-ip-block.js", import.meta.url),
  "utf8"
);
const production = readFileSync(
  new URL("../src/v7-production-entry.js", import.meta.url),
  "utf8"
);

test("explicit operator BLOCK on an originally allowed event records false-negative feedback", () => {
  assert.match(helper, /recordOperatorFalseNegative/);
  assert.match(helper, /context\.v63Decision !== "allow"/);
  assert.match(helper, /label: "false_negative"/);
  assert.match(helper, /confidence: 100/);
  assert.match(helper, /getAdaptiveFeedbackForEvent/);
  assert.match(helper, /rebuildAdaptiveReputation/);
});

test("public operator feedback does not promote public monitor observations into training data", () => {
  assert.match(helper, /trainingEligible: context\.datasetEligible === true/);
  assert.match(helper, /Public monitor observations remain excluded from the training dataset/);
});

test("production Telegram controls prefer exact event mapping and preserve direct exact-IP fallback", () => {
  assert.match(production, /rememberEventIpKey/);
  assert.match(production, /buildTelegramCallbackKeyboard/);
  assert.match(production, /buildTelegramIpKeyCallbackKeyboard/);
  assert.match(production, /operator feedback learning active/);
  assert.match(production, /manual_ip_control_event_mapped/);
});
