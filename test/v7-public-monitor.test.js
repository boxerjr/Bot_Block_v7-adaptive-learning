import test from "node:test";
import assert from "node:assert/strict";
import {
  issueMonitorToken,
  verifyMonitorToken,
} from "../src/adaptive/monitor-token.js";
import {
  buildTelegramDecisionMessage,
  buildTelegramHitMessage,
  coarseUaFamily,
} from "../src/adaptive/telegram.js";

test("monitor token round-trips and rejects wrong secret", async () => {
  const issued = await issueMonitorToken("monitor-secret", 60000);
  const valid = await verifyMonitorToken("monitor-secret", issued.token);
  assert.equal(valid?.type, "m22_public_monitor");
  assert.equal(valid?.sid, issued.payload.sid);

  const invalid = await verifyMonitorToken("wrong-secret", issued.token);
  assert.equal(invalid, null);
});

test("telegram monitor messages are coarse and do not contain raw UA/IP fields", () => {
  const ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1";
  assert.equal(coarseUaFamily(ua), "ios_browser");

  const hit = buildTelegramHitMessage({
    sessionId: "12345678-abcd",
    network: { country: "ES", asn: "AS123", org: "Carrier" },
    early: { outcome: "continue", reason: "no_early_block" },
    uaFamily: coarseUaFamily(ua),
  });
  assert.match(hit, /TRAFFIC_HIT/);
  assert.doesNotMatch(hit, /Mozilla\/5\.0/);
  assert.doesNotMatch(hit, /\b(?:\d{1,3}\.){3}\d{1,3}\b/);

  const final = buildTelegramDecisionMessage({
    sessionId: "12345678-abcd",
    network: { country: "ES", asn: "AS123", org: "Carrier" },
    decision: {
      finalDecision: "allow",
      decisionStage: "post_ai",
      local: { risk: 0, spoofSignals: 0, strongHardwareSpoof: false },
      ai: {
        humanEvidence: 95,
        ai: {
          verdict: "allow",
          classification: "human_mobile",
          classification_confidence: 90,
          human_probability: 95,
          bot_probability: 0,
          spoof_probability: 5,
          risk_score: 5,
        },
      },
    },
    v7: {
      v7Decision: "allow",
      v7Risk: 4,
      baseRisk: 5,
      asnAdjustment: 0,
      fingerprintAdjustment: -1,
      comparison: "same",
    },
    fingerprint: { recentNetworks: 1, seen: 2, risk: 0 },
  });

  assert.match(final, /HUMAN_PASS/);
  assert.match(final, /DatasetEligible: false/);
  assert.match(final, /Enforcing: false/);
  assert.doesNotMatch(final, /Mozilla\/5\.0/);
});
