import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deriveManualIpKey } from "../src/adaptive/manual-ip-block.js";
import {
  buildTelegramOwnerLearningKeyboard,
  parseTelegramIpCallback,
} from "../src/adaptive/telegram-callback.js";
import {
  ownerLearningEnabled,
  recordOwnerHumanConfirmed,
} from "../src/adaptive/owner-learning.js";

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

function fallbackConfirmationDb(eventId, observedAt) {
  let feedbackInserted = false;
  return {
    get feedbackInserted() {
      return feedbackInserted;
    },
    prepare(sql) {
      const statement = String(sql);
      return {
        bind(...args) {
          return {
            async first() {
              if (statement.includes("FROM events")) {
                return {
                  event_id: eventId,
                  asn: null,
                  final_decision: "allow",
                  observed_at: observedAt,
                  telemetry_summary_json: JSON.stringify({ scope: "test", dataset_eligible: false }),
                  adaptive_scope: "test",
                  fingerprint_id: null,
                };
              }
              if (statement.includes("FROM adaptive_live_capture_sessions")) return null;
              if (statement.includes("FROM adaptive_feedback WHERE event_id")) return null;
              return null;
            },
            async all() {
              return { results: [] };
            },
            async run() {
              if (statement.includes("INSERT INTO adaptive_feedback")) feedbackInserted = true;
              return { meta: { changes: 1 } };
            },
          };
        },
      };
    },
  };
}

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

test("IT'S ME recovers when the timer row was lost but the event is still inside three minutes", async () => {
  const eventId = "12345678-abcd-4444-8888-123456789abc";
  const nowMs = 1_800_000_060_000;
  const db = fallbackConfirmationDb(eventId, new Date(nowMs - 60_000).toISOString());
  const result = await recordOwnerHumanConfirmed(db, eventId, nowMs);

  assert.equal(result.learned, true);
  assert.equal(result.label, "human_confirmed");
  assert.equal(db.feedbackInserted, true);
});
