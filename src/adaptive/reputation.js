const DAY_MS = 86_400_000;
const PRIOR_WEIGHT = 4;

export const ADAPTIVE_LABELS = new Set([
  "human_confirmed",
  "bot_confirmed",
  "spoof_confirmed",
  "false_positive",
  "false_negative",
  "uncertain",
]);

const HARD_V63_STAGES = new Set([
  "honeypot",
  "country",
  "hard_asn",
  "verified_bot",
  "strong_bot_ua",
  "obvious_desktop",
  "local_hard_block",
]);

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function feedbackSide(label) {
  if (label === "human_confirmed" || label === "false_positive") return "human";
  if (
    label === "bot_confirmed" ||
    label === "spoof_confirmed" ||
    label === "false_negative"
  ) return "hostile";
  return "neutral";
}

function labelMultiplier(label) {
  if (label === "false_positive" || label === "false_negative") return 1.25;
  if (label === "spoof_confirmed") return 1.1;
  return 1;
}

function halfLifeDays(entityType) {
  return entityType === "fingerprint" ? 14 : 30;
}

export function computeReputationFromFeedback(
  rows = [],
  { entityType = "asn", nowMs = Date.now() } = {}
) {
  let humanWeight = 0;
  let hostileWeight = 0;
  let feedbackCount = 0;

  for (const row of rows) {
    if (!ADAPTIVE_LABELS.has(row?.label)) continue;
    const side = feedbackSide(row.label);
    if (side === "neutral") continue;

    const createdMs = Date.parse(row.created_at || "");
    const ageMs = Number.isFinite(createdMs) ? Math.max(0, nowMs - createdMs) : 0;
    const decay = Math.pow(0.5, ageMs / (halfLifeDays(entityType) * DAY_MS));
    const confidence = clamp(row.confidence, 0, 100) / 100;
    const weight = confidence * labelMultiplier(row.label) * decay;

    if (side === "human") humanWeight += weight;
    if (side === "hostile") hostileWeight += weight;
    feedbackCount += 1;
  }

  const evidenceWeight = humanWeight + hostileWeight;
  const balance = humanWeight - hostileWeight;
  const reputationScore = clamp(
    50 + 50 * (balance / (evidenceWeight + PRIOR_WEIGHT)),
    0,
    100
  );

  return {
    reputationScore: Number(reputationScore.toFixed(3)),
    humanWeight: Number(humanWeight.toFixed(6)),
    hostileWeight: Number(hostileWeight.toFixed(6)),
    evidenceWeight: Number(evidenceWeight.toFixed(6)),
    feedbackCount,
  };
}

export function reputationRiskAdjustment(
  reputation,
  { maxAdjustment = 15 } = {}
) {
  const score = clamp(reputation?.reputationScore ?? 50, 0, 100);
  const evidence = Math.max(0, Number(reputation?.evidenceWeight || 0));
  if (evidence <= 0) return 0;

  const reliability = evidence / (evidence + PRIOR_WEIGHT);
  const signedRisk = (50 - score) / 50;
  return Math.round(signedRisk * maxAdjustment * reliability);
}

export function computeV7ShadowDecision({
  v63Decision = "unknown",
  decisionStage = "post_ai",
  localRisk = 0,
  ai1 = null,
  ai2 = null,
  asnReputation = null,
  fingerprintReputation = null,
} = {}) {
  const asnAdjustment = reputationRiskAdjustment(asnReputation, {
    maxAdjustment: 12,
  });
  const fingerprintAdjustment = reputationRiskAdjustment(fingerprintReputation, {
    maxAdjustment: 20,
  });

  const aiRisk = Math.max(
    Number(ai1?.risk_score || 0),
    Number(ai2?.risk_score || 0)
  );
  const baseRisk = Math.max(clamp(localRisk), clamp(aiRisk));
  const v7Risk = Math.round(clamp(baseRisk + asnAdjustment + fingerprintAdjustment));
  const reasons = [`base_risk:${baseRisk}`];

  if (asnAdjustment !== 0) {
    reasons.push(`asn_reputation:${asnAdjustment > 0 ? "+" : ""}${asnAdjustment}`);
  }
  if (fingerprintAdjustment !== 0) {
    reasons.push(
      `fingerprint_reputation:${fingerprintAdjustment > 0 ? "+" : ""}${fingerprintAdjustment}`
    );
  }

  let v7Decision;

  if (v63Decision === "block" && HARD_V63_STAGES.has(decisionStage)) {
    v7Decision = "block";
    reasons.push(`preserve_hard_policy:${decisionStage}`);
  } else if (v7Risk >= 68) {
    v7Decision = "block";
    reasons.push("adaptive_risk_block");
  } else if (v7Risk >= 50) {
    v7Decision = "review";
    reasons.push("adaptive_risk_review");
  } else {
    v7Decision = "allow";
    reasons.push("adaptive_risk_allow");
  }

  return {
    v7Decision,
    v7Risk,
    baseRisk,
    asnAdjustment,
    fingerprintAdjustment,
    comparison: v7Decision === v63Decision ? "same" : "different",
    reasons,
  };
}
