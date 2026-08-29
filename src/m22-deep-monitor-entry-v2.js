import m22Worker from "./m22-monitor-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { deriveAdaptiveFingerprintId } from "./adaptive/fingerprint-id.js";
import { sanitizeLiveFeatureSummary } from "./adaptive/live-features.js";
import { runMonitorDeepInspection } from "./adaptive/monitor-deep-inspection.js";
import { verifyMonitorToken } from "./adaptive/monitor-token.js";
import {
  buildTelegramDecisionMessage,
  sendTelegram,
} from "./adaptive/telegram.js";
import {
  computeV7ShadowDecision,
  decayStoredReputation,
} from "./adaptive/reputation.js";
import {
  adaptiveSchemaReady,
  getAdaptiveReputations,
  insertAdaptiveShadowObservation,
  recordAdaptiveObservationEntities,
} from "./storage/adaptive-d1.js";
import { insertEvent } from "./storage/d1.js";

const VERSION = "V7.0_M2_2_PUBLIC_MONITOR";
const BASELINE = "V6.3_SILENT_AI";

function compactEarly(early) {
  if (!early) return null;
  return {
    outcome: early.outcome,
    stage: early.stage,
    reason: early.reason,
  };
}

function compactGate(gate) {
  if (!gate) return null;
  return {
    outcome: gate.outcome,
    stage: gate.stage,
    reason: gate.reason,
    device: gate.device || null,
  };
}

function compactFingerprint(fp) {
  return {
    recentNetworks: Number(fp?.recentNetworks || 0),
    seen: Number(fp?.seen || 0),
    risk: Number(fp?.risk || 0),
    reasons: Array.isArray(fp?.reasons) ? fp.reasons : [],
    stored: fp?.stored === true,
    reason: fp?.reason || null,
  };
}

function compactAi(ai) {
  if (!ai) return null;
  return {
    run: !!ai.runAi,
    critic_run: !!ai.criticRun,
    skipped_reason: ai.skippedReason || null,
    ai1: ai.ai || null,
    ai2: ai.critic || null,
    human_evidence: Number(ai.humanEvidence || 0),
    hard_local_block: !!ai.hardLocalBlock,
    error: ai.error || null,
  };
}

function compactReputation(rep) {
  if (!rep) return null;
  return {
    reputation_score: Number(rep.reputationScore ?? 50),
    human_weight: Number(rep.humanWeight || 0),
    hostile_weight: Number(rep.hostileWeight || 0),
    evidence_weight: Number(rep.evidenceWeight || 0),
    feedback_count: Number(rep.feedbackCount || 0),
    observation_count: Number(rep.observationCount || 0),
  };
}

function applyReadDecay(reputations, nowMs = Date.now()) {
  const asn = decayStoredReputation(reputations?.asn, {
    entityType: "asn",
    nowMs,
    lastFeedbackAt: reputations?.asn?.lastFeedbackAt || null,
  });
  const fingerprint = decayStoredReputation(reputations?.fingerprint, {
    entityType: "fingerprint",
    nowMs,
    lastFeedbackAt: reputations?.fingerprint?.lastFeedbackAt || null,
  });
  return {
    asn: { ...(reputations?.asn || {}), ...asn },
    fingerprint: { ...(reputations?.fingerprint || {}), ...fingerprint },
  };
}

async function consumeMonitorSession(db, sid, nowMs = Date.now()) {
  const result = await db
    .prepare(
      `UPDATE adaptive_live_capture_sessions
       SET consumed_at_ms = ?
       WHERE sid = ?
         AND consumed_at_ms IS NULL
         AND expires_at_ms > ?`
    )
    .bind(nowMs, sid, nowMs)
    .run();
  return Number(result?.meta?.changes || 0) === 1;
}

function waitUntil(ctx, promise) {
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else return promise;
}

async function healthWithDeepInspection(request, env, ctx) {
  const response = await m22Worker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  return Response.json(
    {
      ...data,
      m22_policy_baseline_preserved: true,
      m22_deep_inspection_after_policy_blocks: true,
      m22_deep_inspection_after_country_block: true,
      m22_deep_inspection_after_device_block: true,
      m22_deep_inspection_runs_ai: true,
      m22_deep_inspection_enforcing: false,
      m22_deep_inspection_dataset_eligible: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function handleDeepMonitorSubmit(request, env, ctx) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!env.CHALLENGE_SECRET) {
    return Response.json({ error: "challenge_secret_missing" }, { status: 503 });
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > 120000) {
    return Response.json({ error: "payload_too_large" }, { status: 413 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }

  const tokenPayload = await verifyMonitorToken(
    env.CHALLENGE_SECRET,
    body?.token || ""
  );
  if (!tokenPayload) {
    return Response.json({ error: "invalid_or_expired_monitor_token" }, { status: 401 });
  }

  const consumed = await consumeMonitorSession(env.DB, tokenPayload.sid);
  if (!consumed) {
    return Response.json({ error: "monitor_token_already_used_or_expired" }, { status: 409 });
  }

  const telemetry =
    body?.telemetry && typeof body.telemetry === "object" ? body.telemetry : {};
  const ua = request.headers.get("user-agent") || "";
  const network = networkInfo(request);
  const ip = clientIp(request);

  const decision = await runMonitorDeepInspection({
    request,
    env,
    network,
    ip,
    ua,
    telemetry,
    targetPath: "/",
  });

  const policyBaseline = decision.policyBaseline || {
    finalDecision: decision.finalDecision,
    wouldBlock: decision.finalDecision === "block",
    decisionStage: decision.decisionStage,
    reason: decision.finalDecision === "block" ? "v63_detection_block" : "v63_allow",
  };

  const event = buildEvent({
    network,
    local: {
      risk: Number(decision.local?.risk || 0),
      spoofSignals: Number(decision.local?.spoofSignals || 0),
      strongHardwareSpoof: !!decision.local?.strongHardwareSpoof,
      reasons: Array.isArray(decision.local?.reasons) ? decision.local.reasons : [],
    },
    ai1: decision.ai?.ai || null,
    ai2: decision.ai?.critic || null,
    decision: decision.finalDecision,
    finalReasons: [
      "shadow_only",
      "public_traffic_monitor",
      ...(decision.monitorDeepInspection ? ["monitor_deep_inspection"] : []),
      ...(decision.finalReasons || []),
    ],
    telemetrySummary: {
      mode: "shadow",
      baseline: BASELINE,
      source: "public_traffic_monitor",
      scope: "live",
      dataset_eligible: false,
      training_eligible: false,
      deep_inspection: !!decision.monitorDeepInspection,
      policy_baseline: {
        decision: policyBaseline.finalDecision,
        stage: policyBaseline.decisionStage,
        reason: policyBaseline.reason || null,
        would_block: !!policyBaseline.wouldBlock,
        early_rules: compactEarly(decision.early),
        device_gate: compactGate(decision.deviceGate),
      },
      sanitized_feature_summary: sanitizeLiveFeatureSummary({ ua, telemetry }),
      detection_stage: decision.decisionStage,
      early_rules: compactEarly(decision.early),
      device_gate: compactGate(decision.deviceGate),
      fingerprint: compactFingerprint(decision.fingerprint),
      ai: {
        run: !!decision.ai?.runAi,
        critic_run: !!decision.ai?.criticRun,
        human_evidence: Number(decision.ai?.humanEvidence || 0),
        hard_local_block: !!decision.ai?.hardLocalBlock,
        error_present: !!decision.ai?.error,
      },
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      ai_decision_used_as_training_label: false,
    },
  });

  let d1Written = false;
  try {
    await insertEvent(env.DB, event);
    d1Written = true;
  } catch {}

  let adaptiveWritten = false;
  let v7 = null;
  let reputations = null;

  if (d1Written && (await adaptiveSchemaReady(env.DB))) {
    try {
      const fingerprintId = await deriveAdaptiveFingerprintId(
        env.CHALLENGE_SECRET,
        { ua, telemetry }
      );
      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();

      await recordAdaptiveObservationEntities(env.DB, {
        scope: "live",
        asn: network.asn || null,
        fingerprintId,
        nowIso,
      });

      const stored = await getAdaptiveReputations(env.DB, {
        scope: "live",
        asn: network.asn || null,
        fingerprintId,
      });
      reputations = applyReadDecay(stored, nowMs);

      v7 = computeV7ShadowDecision({
        v63Decision: decision.finalDecision || "unknown",
        decisionStage: decision.decisionStage || "post_ai",
        localRisk: Number(decision.local?.risk || 0),
        ai1: decision.ai?.ai || null,
        ai2: decision.ai?.critic || null,
        asnReputation: reputations.asn,
        fingerprintReputation: reputations.fingerprint,
      });

      await insertAdaptiveShadowObservation(env.DB, {
        eventId: event.event_id,
        scope: "live",
        asn: network.asn || null,
        fingerprintId,
        v63Decision: decision.finalDecision || "unknown",
        v63Risk: Number(decision.local?.risk || 0),
        v7,
        asnReputation: reputations.asn,
        fingerprintReputation: reputations.fingerprint,
        datasetEligible: false,
        nowIso,
      });
      adaptiveWritten = true;
    } catch {}
  }

  const telegramCore = buildTelegramDecisionMessage({
    sessionId: tokenPayload.sid,
    network,
    decision,
    v7,
    fingerprint: decision.fingerprint,
  });
  const policyLine = `PolicyV6.3: ${policyBaseline.finalDecision || "unknown"} stage=${policyBaseline.decisionStage || "unknown"} reason=${policyBaseline.reason || "unknown"}`;
  const countryLine = `CountryGate: ${decision.early?.outcome || "unknown"} stage=${decision.early?.stage || "unknown"} reason=${decision.early?.reason || "unknown"}`;
  const deviceLine = `DeviceGate: ${decision.deviceGate?.outcome || "unknown"} stage=${decision.deviceGate?.stage || "unknown"} reason=${decision.deviceGate?.reason || "unknown"}`;
  const inspectionLine = decision.monitorDeepInspection
    ? "MonitorDeepInspection: continued through local/fingerprint/AI"
    : "MonitorDeepInspection: policy gates passed normally";
  waitUntil(
    ctx,
    sendTelegram(
      env,
      `${telegramCore}\n${policyLine}\n${countryLine}\n${deviceLine}\n${inspectionLine}`
    )
  );

  return Response.json(
    {
      status: "m22_public_monitor_observation",
      m22_version: VERSION,
      baseline: BASELINE,
      enforcing: false,
      scope: "live",
      dataset_eligible: false,
      training_eligible: false,
      event_id: event.event_id,
      token_consumed: true,
      d1_written: d1Written,
      r2_written: false,
      adaptive_observation_written: adaptiveWritten,
      telegram_configured: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID,
      policy_baseline: {
        final_decision: policyBaseline.finalDecision,
        would_block: !!policyBaseline.wouldBlock,
        decision_stage: policyBaseline.decisionStage,
        reason: policyBaseline.reason || null,
        early_rules: compactEarly(decision.early),
        device_gate: compactGate(decision.deviceGate),
      },
      monitor_deep_inspection: !!decision.monitorDeepInspection,
      monitor_detection: {
        final_decision: decision.finalDecision,
        would_block: decision.finalDecision === "block",
        decision_stage: decision.decisionStage,
      },
      final_decision: decision.finalDecision,
      would_block: decision.finalDecision === "block",
      decision_stage: decision.decisionStage,
      early_rules: compactEarly(decision.early),
      device_gate: compactGate(decision.deviceGate),
      fingerprint: compactFingerprint(decision.fingerprint),
      local: {
        risk: Number(decision.local?.risk || 0),
        spoofSignals: Number(decision.local?.spoofSignals || 0),
        strongHardwareSpoof: !!decision.local?.strongHardwareSpoof,
        critical: !!decision.local?.critical,
        reasons: Array.isArray(decision.local?.reasons) ? decision.local.reasons : [],
      },
      ai: compactAi(decision.ai),
      v7_shadow: v7
        ? {
            ready: true,
            enforcing: false,
            decision: v7.v7Decision,
            risk: v7.v7Risk,
            comparison: v7.comparison,
            base_risk: v7.baseRisk,
            asn_adjustment: v7.asnAdjustment,
            fingerprint_adjustment: v7.fingerprintAdjustment,
            asn_reputation: compactReputation(reputations?.asn),
            fingerprint_reputation: compactReputation(reputations?.fingerprint),
          }
        : { ready: false },
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      ai_decision_used_as_training_label: false,
    },
    { status: 201, headers: { "cache-control": "no-store" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return healthWithDeepInspection(request, env, ctx);
    }
    if (url.pathname === "/_shadow/v7-monitor-submit") {
      return handleDeepMonitorSubmit(request, env, ctx);
    }

    return m22Worker.fetch(request, env, ctx);
  },
};
