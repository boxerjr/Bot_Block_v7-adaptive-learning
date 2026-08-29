import test from "node:test";
import assert from "node:assert/strict";
import {
  computeReputationFromFeedback,
  decayStoredReputation,
  reputationRiskAdjustment,
  computeV7ShadowDecision,
} from "../src/adaptive/reputation.js";
import { deriveAdaptiveFingerprintId } from "../src/adaptive/fingerprint-id.js";

const NOW = Date.parse("2026-08-29T12:00:00.000Z");

function row(label, confidence = 100, createdAt = "2026-08-29T12:00:00.000Z") {
  return { label, confidence, created_at: createdAt };
}

test("no explicit feedback keeps reputation neutral", () => {
  const rep = computeReputationFromFeedback([], { entityType: "asn", nowMs: NOW });
  assert.equal(rep.reputationScore, 50);
  assert.equal(rep.evidenceWeight, 0);
  assert.equal(reputationRiskAdjustment(rep), 0);
});

test("confirmed human raises trust and confirmed bot lowers trust", () => {
  const human = computeReputationFromFeedback([row("human_confirmed")], {
    entityType: "asn",
    nowMs: NOW,
  });
  const bot = computeReputationFromFeedback([row("bot_confirmed")], {
    entityType: "asn",
    nowMs: NOW,
  });

  assert.ok(human.reputationScore > 50);
  assert.ok(bot.reputationScore < 50);
  assert.ok(reputationRiskAdjustment(human) < 0);
  assert.ok(reputationRiskAdjustment(bot) > 0);
});

test("uncertain feedback does not train reputation", () => {
  const rep = computeReputationFromFeedback([row("uncertain")], {
    entityType: "fingerprint",
    nowMs: NOW,
  });
  assert.equal(rep.reputationScore, 50);
  assert.equal(rep.evidenceWeight, 0);
  assert.equal(rep.feedbackCount, 0);
});

test("older feedback decays and fingerprint evidence decays faster than ASN evidence", () => {
  const old = "2026-07-30T12:00:00.000Z";
  const asn = computeReputationFromFeedback([row("bot_confirmed", 100, old)], {
    entityType: "asn",
    nowMs: NOW,
  });
  const fp = computeReputationFromFeedback([row("bot_confirmed", 100, old)], {
    entityType: "fingerprint",
    nowMs: NOW,
  });

  assert.ok(asn.evidenceWeight > fp.evidenceWeight);
  assert.ok(asn.reputationScore < fp.reputationScore);
});

test("cached reputation keeps decaying toward neutral without new feedback", () => {
  const fresh = computeReputationFromFeedback([row("bot_confirmed")], {
    entityType: "asn",
    nowMs: NOW,
  });
  const afterThirtyDays = decayStoredReputation(fresh, {
    entityType: "asn",
    nowMs: NOW + 30 * 86_400_000,
    lastFeedbackAt: "2026-08-29T12:00:00.000Z",
  });

  assert.ok(afterThirtyDays.evidenceWeight < fresh.evidenceWeight);
  assert.ok(afterThirtyDays.reputationScore > fresh.reputationScore);
  assert.ok(afterThirtyDays.reputationScore < 50);
});

test("false positive and false negative carry stronger corrective weight", () => {
  const human = computeReputationFromFeedback([row("false_positive")], {
    entityType: "asn",
    nowMs: NOW,
  });
  const hostile = computeReputationFromFeedback([row("false_negative")], {
    entityType: "asn",
    nowMs: NOW,
  });
  const plainHuman = computeReputationFromFeedback([row("human_confirmed")], {
    entityType: "asn",
    nowMs: NOW,
  });

  assert.ok(human.humanWeight > plainHuman.humanWeight);
  assert.ok(hostile.hostileWeight > 1);
});

test("V7 preserves V6.3 hard policy blocks regardless of neutral reputation", () => {
  const v7 = computeV7ShadowDecision({
    v63Decision: "block",
    decisionStage: "country",
    localRisk: 0,
  });

  assert.equal(v7.v7Decision, "block");
  assert.equal(v7.comparison, "same");
  assert.ok(v7.reasons.includes("preserve_hard_policy:country"));
});

test("V7 can produce a shadow disagreement without affecting enforcement", () => {
  const hostileRep = {
    reputationScore: 0,
    evidenceWeight: 100,
  };
  const v7 = computeV7ShadowDecision({
    v63Decision: "allow",
    decisionStage: "post_ai",
    localRisk: 45,
    asnReputation: hostileRep,
    fingerprintReputation: hostileRep,
  });

  assert.ok(v7.v7Risk > 45);
  assert.notEqual(v7.v7Decision, "allow");
  assert.equal(v7.comparison, "different");
});

test("adaptive fingerprint id is deterministic, keyed, and does not expose raw UA", async () => {
  const ua = "Mozilla/5.0 TEST-RAW-UA";
  const input = {
    ua,
    telemetry: {
      navigator: {
        platform: "iPhone",
        vendor: "Apple Computer, Inc.",
        hardwareConcurrency: 6,
        maxTouchPoints: 5,
      },
      webgl: { renderer: "Apple GPU" },
      screen: { width: 390, height: 844, pixelRatio: 3 },
      timezone: { name: "Europe/Madrid" },
    },
  };

  const a = await deriveAdaptiveFingerprintId("secret-a", input);
  const b = await deriveAdaptiveFingerprintId("secret-a", input);
  const c = await deriveAdaptiveFingerprintId("secret-b", input);

  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^v7fp_[A-Za-z0-9_-]{32}$/);
  assert.equal(a.includes("TEST-RAW-UA"), false);
});
