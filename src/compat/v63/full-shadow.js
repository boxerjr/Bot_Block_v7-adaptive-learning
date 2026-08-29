import { boolEnv, csvSet } from "../../engine/config.js";
import { evaluateV63EarlyRules } from "./preflight.js";
import { evaluateV63MobileGate } from "./device.js";
import { fingerprintV63Reputation } from "./fingerprint.js";
import { scoreV63Signals } from "./score-signals.js";
import { buildV63AiFeatures, runV63AiPipeline } from "./ai.js";

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

function emptyAi(reason = "not_run") {
  return {
    runAi: false,
    criticRun: false,
    ai: null,
    critic: null,
    error: null,
    wouldBlock: false,
    finalReasons: [],
    humanEvidence: 0,
    hardLocalBlock: false,
    skippedReason: reason,
  };
}

function emptyLocal() {
  return {
    risk: 0,
    reasons: [],
    critical: false,
    spoofSignals: 0,
    strongHardwareSpoof: false,
  };
}

/**
 * Full V6.3 M1 shadow orchestrator.
 *
 * Decision order intentionally mirrors the compatibility baseline:
 * early request rules -> MOBILE_ONLY gate -> local score -> fingerprint
 * reputation -> local hard block / Workers AI -> final allow/block.
 *
 * It never enforces traffic. Callers may persist the sanitized result.
 */
export async function runV63FullShadowDecision({
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

  if (early.outcome === "block") {
    return {
      finalDecision: "block",
      decisionStage: early.stage,
      finalReasons: [`early:${early.reason}`],
      early,
      deviceGate: null,
      local: emptyLocal(),
      fingerprint: emptyFingerprint("skipped_after_early_block"),
      ai: emptyAi("skipped_after_early_block"),
    };
  }

  const deviceGate = evaluateV63MobileGate({
    ua,
    chMobile: request?.headers?.get?.("sec-ch-ua-mobile") ?? null,
    mobileOnly: boolEnv(env.MOBILE_ONLY, true),
  });

  if (deviceGate.outcome === "block") {
    return {
      finalDecision: "block",
      decisionStage: deviceGate.stage,
      finalReasons: [`device:${deviceGate.reason}`],
      early,
      deviceGate,
      local: emptyLocal(),
      fingerprint: emptyFingerprint("skipped_after_device_block"),
      ai: emptyAi("skipped_after_device_block"),
    };
  }

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
  } catch (error) {
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

  return {
    finalDecision: ai.wouldBlock ? "block" : "allow",
    decisionStage: ai.hardLocalBlock ? "local_hard_block" : "post_ai",
    finalReasons: ai.wouldBlock
      ? (ai.finalReasons.length ? ai.finalReasons : ["v63_block"])
      : ["v63_allow"],
    early,
    deviceGate,
    local,
    fingerprint,
    ai,
  };
}
