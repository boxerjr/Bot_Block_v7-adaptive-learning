function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function aiDecisions(decision = {}) {
  return [decision.ai?.ai, decision.ai?.critic].filter(Boolean);
}

function combinedText(decision = {}) {
  const parts = [
    ...(Array.isArray(decision.local?.reasons) ? decision.local.reasons : []),
  ];
  for (const ai of aiDecisions(decision)) {
    parts.push(ai.classification || "");
    if (Array.isArray(ai.reasons)) parts.push(...ai.reasons);
  }
  return parts.join(" ").toLowerCase();
}

/**
 * Policy-neutral verdict for the public diagnostic monitor.
 *
 * V6.3 remains mobile-only and is preserved separately as policy/v63 detection.
 * This helper only answers: does the observed browser look like a human,
 * automation/crawler, spoofed device, or an uncertain case?
 *
 * A coherent desktop is NOT bot evidence by itself.
 */
export function deriveMonitorVerdict(decision = {}) {
  const local = decision.local || {};
  const ais = aiDecisions(decision);
  const classes = new Set(ais.map((ai) => String(ai.classification || "").toLowerCase()));
  const maxBot = Math.max(0, ...ais.map((ai) => Number(ai.bot_probability || 0)));
  const maxSpoof = Math.max(0, ...ais.map((ai) => Number(ai.spoof_probability || 0)));
  const maxRisk = Math.max(Number(local.risk || 0), ...ais.map((ai) => Number(ai.risk_score || 0)));
  const maxConfidence = Math.max(0, ...ais.map((ai) => Number(ai.classification_confidence || 0)));
  const text = combinedText(decision);

  const explicitAutomation =
    classes.has("automation") ||
    classes.has("crawler") ||
    /webdriver|selenium|playwright|puppeteer|phantom|headless|automation|crawler/.test(text);

  const localSpoofEvidence =
    !!local.strongHardwareSpoof ||
    Number(local.spoofSignals || 0) > 0;

  const coherentDesktop =
    decision.deviceGate?.device === "desktop" &&
    Number(local.risk || 0) <= 15 &&
    Number(local.spoofSignals || 0) === 0 &&
    !local.strongHardwareSpoof &&
    maxBot < 50 &&
    !explicitAutomation;

  if (coherentDesktop) {
    return {
      decision: "allow",
      classification: "human_desktop",
      confidence: clamp(Math.max(80, maxConfidence)),
      risk: clamp(Math.min(15, Number(local.risk || 0) + maxBot)),
      reasons: [
        "coherent_desktop_environment",
        "desktop_policy_mismatch_is_not_bot_evidence",
        "no_local_automation_or_spoof_signals",
      ],
      source: "policy_neutral_monitor",
    };
  }

  if (explicitAutomation || maxBot >= 80) {
    return {
      decision: "block",
      classification: classes.has("crawler") ? "crawler" : "automation",
      confidence: clamp(Math.max(60, maxConfidence)),
      risk: clamp(Math.max(maxRisk, maxBot)),
      reasons: ["automation_or_crawler_evidence"],
      source: "policy_neutral_monitor",
    };
  }

  if (localSpoofEvidence || (maxSpoof >= 78 && Number(local.risk || 0) >= 25)) {
    return {
      decision: "block",
      classification: "spoofed_device",
      confidence: clamp(Math.max(60, maxConfidence)),
      risk: clamp(Math.max(maxRisk, maxSpoof)),
      reasons: ["spoof_evidence_beyond_policy_mismatch"],
      source: "policy_neutral_monitor",
    };
  }

  if (decision.finalDecision === "allow") {
    const mobileHuman = classes.has("human_mobile") || decision.deviceGate?.device === "mobile";
    return {
      decision: "allow",
      classification: mobileHuman ? "human_mobile" : "human_unknown",
      confidence: clamp(Math.max(60, maxConfidence)),
      risk: clamp(Math.min(49, maxRisk)),
      reasons: ["v63_detection_allow_without_hostile_monitor_evidence"],
      source: "policy_neutral_monitor",
    };
  }

  return {
    decision: "review",
    classification: "unknown",
    confidence: clamp(maxConfidence),
    risk: clamp(Math.max(50, Math.min(67, maxRisk || 50))),
    reasons: ["v63_block_not_supported_by_policy_neutral_hostile_evidence"],
    source: "policy_neutral_monitor",
  };
}
