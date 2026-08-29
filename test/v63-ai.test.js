import test from "node:test";
import assert from "node:assert/strict";

import {
  parseV63AiResult,
  v63AiIsInternallyInconsistent,
  needsV63Critic,
  evaluateV63AiDecision,
} from "../src/compat/v63/ai.js";

function ai(overrides = {}) {
  return {
    verdict: "allow",
    classification: "human_mobile",
    classification_confidence: 90,
    human_probability: 95,
    bot_probability: 1,
    spoof_probability: 2,
    risk_score: 3,
    reasons: ["coherent_mobile"],
    ...overrides,
  };
}

test("confidence_v2 parser clamps probabilities and limits reasons", () => {
  const parsed = parseV63AiResult({
    response: JSON.stringify({
      verdict: "allow",
      classification: "human_mobile",
      classification_confidence: 120,
      human_probability: 101,
      bot_probability: -2,
      spoof_probability: 4,
      risk_score: 5,
      reasons: ["1", "2", "3", "4", "5", "6", "7"],
    }),
  });

  assert.equal(parsed.classification_confidence, 100);
  assert.equal(parsed.human_probability, 100);
  assert.equal(parsed.bot_probability, 0);
  assert.equal(parsed.reasons.length, 6);
});

test("allow with high spoof probability is internally inconsistent", () => {
  assert.equal(v63AiIsInternallyInconsistent(ai({ spoof_probability: 80 })), true);
});

test("review verdict triggers critic when dual review is enabled", () => {
  assert.equal(
    needsV63Critic(
      { AI_DUAL_REVIEW: "true", AI_CRITIC_MIN_CONFIDENCE: "70" },
      { risk: 0, spoofSignals: 0, strongHardwareSpoof: false },
      ai({ verdict: "review" })
    ),
    true
  );
});

test("strong hardware spoof always triggers critic", () => {
  assert.equal(
    needsV63Critic(
      { AI_DUAL_REVIEW: "true" },
      { risk: 75, spoofSignals: 3, strongHardwareSpoof: true },
      ai()
    ),
    true
  );
});

test("AI high spoof probability blocks at V6.3 default thresholds", () => {
  const decision = evaluateV63AiDecision({
    env: {},
    local: { risk: 0, spoofSignals: 0, strongHardwareSpoof: false },
    ai: ai({ spoof_probability: 90, classification_confidence: 90 }),
    critic: null,
  });

  assert.equal(decision.block, true);
  assert.ok(decision.finalReasons.includes("AI1_high_spoof_probability"));
});

test("clean high-confidence human remains allowed", () => {
  const decision = evaluateV63AiDecision({
    env: {},
    local: { risk: 0, spoofSignals: 0, strongHardwareSpoof: false },
    ai: ai(),
    critic: null,
  });

  assert.equal(decision.block, false);
  assert.equal(decision.humanEvidence, 95);
});

test("strong hardware spoof cannot be neutralized by one AI allow", () => {
  const decision = evaluateV63AiDecision({
    env: {},
    local: { risk: 75, spoofSignals: 3, strongHardwareSpoof: true },
    ai: ai({ human_probability: 99, spoof_probability: 1 }),
    critic: null,
  });

  assert.equal(decision.block, true);
  assert.ok(decision.finalReasons.includes("strong_hardware_spoof"));
});

test("extraordinary dual human consensus is the V6.3 hardware exception", () => {
  const human = ai({ human_probability: 99, spoof_probability: 1, risk_score: 1 });
  const decision = evaluateV63AiDecision({
    env: {},
    local: { risk: 75, spoofSignals: 3, strongHardwareSpoof: true },
    ai: human,
    critic: human,
  });

  assert.equal(decision.block, false);
});
