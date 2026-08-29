import { csvSet, boolEnv } from "../engine/config.js";
import { evaluateV63EarlyRules } from "../compat/v63/preflight.js";
import { evaluateV63MobileGate } from "../compat/v63/device.js";
import { fingerprintV63Reputation } from "../compat/v63/fingerprint.js";
import { scoreV63Signals } from "../compat/v63/score-signals.js";
import { buildV63AiFeatures, runV63AiPipeline } from "../compat/v63/ai.js";
import { deriveMonitorVerdict } from "./monitor-verdict.js";

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function emptyFingerprint(reason = "not_run") {
  return {
    fpHash: null,
    recentNetworks: 0,
    seen: 0,
    risk: 0,
    reasons: [],
    stored: false,
    reason,
  };
}

/**
 * M2.2 monitor-only deep inspection.
 *
 * V6.3 policy gates are evaluated and preserved, but the public monitor continues
 * through local scoring, fingerprint reputation and Workers AI. A second,
 * policy-neutral monitor verdict then separates "site policy would reject this"
 * from "this actually looks automated/spoofed".
 *
 * No caller should use this function to authorize or enforce traffic.
 */
export async function runMonitorDeepInspection({
  request,
  env = {},
  network = {},
  ip = "unknown",
  ua = "",
  telemetry = {},
  targetPath = "/",
}) {
  const early = evaluateV63EarlyRules({
    path: targetPath,
    ua,
    network,
    allowedCountries: csvSet(env.ALLOWED_COUNTRIES, "ES"),
    humansOnly: boolEnv(env.HUMANS_ONLY, true),
  });

  const deviceGate = evaluateV63MobileGate({
    ua,
    chMobile: request?.headers?.get?.("sec-ch-ua-mobile") ?? null,
    mobileOnly: boolEnv(env.MOBILE_ONLY, true),
  });

  const policyBlock = early.outcome === "block"
    ? {
        finalDecision: "block",
        wouldBlock: true,
        decisionStage: early.stage,
        reason: early.reason,
      }
    : deviceGate.outcome === "block"
      ? {
          finalDecision: "block",
          wouldBlock: true,
          decisionStage: deviceGate.stage,
          reason: deviceGate.reason,
        }
      : null;

  const localBase = scoreV63Signals({ request, env, network, ua, telemetry });

  let fingerprint;
  try {
    fingerprint = await fingerprintV63Reputation({
      db: env.DB,
      ip,
      ua,
      network,
      telemetry,
    });
  } catch {
    fingerprint = emptyFingerprint("fingerprint_state_error");
  }

  const local = {
    ...localBase,
    risk: clamp((localBase.risk || 0) + (fingerprint.risk || 0)),
    reasons: [
      ...(Array.isArray(localBase.reasons) ? localBase.reasons : []),
      ...(Array.isArray(fingerprint.reasons) ? fingerprint.reasons : []),
    ],
  };

  const features = buildV63AiFeatures({
    request,
    env,
    network,
    ua,
    telemetry,
    local,
    fingerprint,
  });

  const ai = await runV63AiPipeline({ env, features, local });

  const v63FinalDecision = ai.wouldBlock ? "block" : "allow";
  const v63DecisionStage = ai.hardLocalBlock ? "local_hard_block" : "post_ai";
  const v63FinalReasons = ai.wouldBlock
    ? (ai.finalReasons.length ? ai.finalReasons : ["v63_detection_block"])
    : ["v63_detection_allow"];

  const v63Detection = {
    finalDecision: v63FinalDecision,
    wouldBlock: v63FinalDecision === "block",
    decisionStage: v63DecisionStage,
    finalReasons: v63FinalReasons,
  };

  const provisional = {
    finalDecision: v63FinalDecision,
    decisionStage: v63DecisionStage,
    finalReasons: v63FinalReasons,
    early,
    deviceGate,
    local,
    fingerprint,
    ai,
  };

  const monitorVerdict = deriveMonitorVerdict(provisional);

  const policyBaseline = policyBlock || {
    finalDecision: v63FinalDecision,
    wouldBlock: v63FinalDecision === "block",
    decisionStage: v63DecisionStage,
    reason: v63FinalDecision === "block" ? "v63_detection_block" : "v63_allow",
  };

  return {
    finalDecision: monitorVerdict.decision,
    decisionStage: "monitor_policy_neutral",
    finalReasons: monitorVerdict.reasons,
    early,
    deviceGate,
    local,
    fingerprint,
    ai,
    policyBaseline,
    v63Detection,
    monitorVerdict,
    monitorDeepInspection: !!policyBlock,
  };
}
