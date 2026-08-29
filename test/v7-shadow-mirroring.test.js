import test from "node:test";
import assert from "node:assert/strict";
import { computeV7ShadowDecision } from "../src/adaptive/reputation.js";

test("neutral reputation mirrors an allowed V6.3 decision even at moderate base risk", () => {
  const v7 = computeV7ShadowDecision({
    v63Decision: "allow",
    decisionStage: "post_ai",
    localRisk: 55,
    asnReputation: { reputationScore: 50, evidenceWeight: 0 },
    fingerprintReputation: { reputationScore: 50, evidenceWeight: 0 },
  });

  assert.equal(v7.v7Decision, "allow");
  assert.equal(v7.comparison, "same");
  assert.ok(v7.reasons.includes("neutral_reputation_mirrors_v63"));
});

test("neutral reputation mirrors a non-hard V6.3 AI block", () => {
  const v7 = computeV7ShadowDecision({
    v63Decision: "block",
    decisionStage: "post_ai",
    localRisk: 20,
    ai1: { risk_score: 75 },
    asnReputation: { reputationScore: 50, evidenceWeight: 0 },
    fingerprintReputation: { reputationScore: 50, evidenceWeight: 0 },
  });

  assert.equal(v7.v7Decision, "block");
  assert.equal(v7.comparison, "same");
});
