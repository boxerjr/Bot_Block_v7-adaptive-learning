import test from "node:test";
import assert from "node:assert/strict";
import { deriveMonitorVerdict } from "../src/adaptive/monitor-verdict.js";
import { buildTelegramDecisionMessage } from "../src/adaptive/telegram.js";

test("coherent real desktop is human_desktop, not bot, in public monitor", () => {
  const decision = {
    finalDecision: "block",
    decisionStage: "post_ai",
    deviceGate: {
      outcome: "block",
      stage: "obvious_desktop",
      reason: "desktop_not_allowed",
      device: "desktop",
    },
    local: {
      risk: 0,
      spoofSignals: 0,
      strongHardwareSpoof: false,
      critical: false,
      reasons: ["safe_access_asn"],
    },
    ai: {
      ai: {
        verdict: "block",
        classification: "desktop_emulation",
        classification_confidence: 0,
        human_probability: 0,
        bot_probability: 0,
        spoof_probability: 100,
        risk_score: 100,
        reasons: ["desktop_platform", "desktop_gpu", "high_cpu_concurrency"],
      },
      critic: {
        verdict: "block",
        classification: "desktop_emulation",
        classification_confidence: 95,
        human_probability: 0,
        bot_probability: 0,
        spoof_probability: 100,
        risk_score: 100,
        reasons: ["desktop_platform", "desktop_gpu", "windows_fonts"],
      },
    },
  };

  const verdict = deriveMonitorVerdict(decision);
  assert.equal(verdict.decision, "allow");
  assert.equal(verdict.classification, "human_desktop");
});

test("automation evidence still blocks in policy-neutral public monitor", () => {
  const decision = {
    finalDecision: "block",
    decisionStage: "post_ai",
    deviceGate: { device: "desktop" },
    local: {
      risk: 100,
      spoofSignals: 2,
      strongHardwareSpoof: true,
      critical: true,
      reasons: ["navigator.webdriver", "selenium_marker"],
    },
    ai: {
      ai: {
        verdict: "block",
        classification: "automation",
        classification_confidence: 95,
        bot_probability: 99,
        spoof_probability: 90,
        risk_score: 100,
        reasons: ["webdriver"],
      },
    },
  };

  const verdict = deriveMonitorVerdict(decision);
  assert.equal(verdict.decision, "block");
  assert.equal(verdict.classification, "automation");
});

test("Telegram title uses monitor verdict and does not let V7Compat relabel clean desktop as bot", () => {
  const monitorVerdict = {
    decision: "allow",
    classification: "human_desktop",
    confidence: 95,
    risk: 0,
    reasons: ["coherent_desktop_environment"],
  };
  const message = buildTelegramDecisionMessage({
    sessionId: "12345678-test",
    network: { country: "RO", asn: "AS14593", org: "Example" },
    decision: {
      finalDecision: "allow",
      decisionStage: "monitor_policy_neutral",
      monitorVerdict,
      local: { risk: 0, spoofSignals: 0, strongHardwareSpoof: false },
      ai: { humanEvidence: 0 },
    },
    v7: { v7Decision: "block", v7Risk: 100, baseRisk: 100 },
    policyBaseline: {
      finalDecision: "block",
      wouldBlock: true,
      decisionStage: "country",
      reason: "blocked_country",
    },
    monitorDeepInspection: true,
  });

  assert.match(message, /^🖥️ HUMAN_DESKTOP/m);
  assert.match(message, /MonitorDetection: allow class=human_desktop/);
  assert.match(message, /V7Compat: block risk=100/);
});
