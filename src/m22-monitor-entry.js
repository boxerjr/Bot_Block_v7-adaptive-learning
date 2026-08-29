import m21Worker from "./m21-live-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { deriveAdaptiveFingerprintId } from "./adaptive/fingerprint-id.js";
import { sanitizeLiveFeatureSummary } from "./adaptive/live-features.js";
import { monitorBrowserProbeHtml } from "./adaptive/monitor-probe.js";
import { issueMonitorToken, verifyMonitorToken } from "./adaptive/monitor-token.js";
import { runMonitorDeepInspection } from "./adaptive/monitor-deep-inspection.js";
import {
  buildTelegramDecisionMessage,
  buildTelegramHitMessage,
  coarseUaFamily,
  sendTelegram,
} from "./adaptive/telegram.js";
import {
  computeV7ShadowDecision,
  decayStoredReputation,
} from "./adaptive/reputation.js";
import { evaluateV63EarlyRules } from "./compat/v63/preflight.js";
import {
  adaptiveSchemaReady,
  getAdaptiveReputations,
  insertAdaptiveShadowObservation,
  recordAdaptiveObservationEntities,
} from "./storage/adaptive-d1.js";
import { insertEvent } from "./storage/d1.js";

const VERSION = "V7.0_M2_2_PUBLIC_MONITOR";
const BASELINE = "V6.3_SILENT_AI";

function allowedCountries(env) {
  const values = String(env.ALLOWED_COUNTRIES || "ES")
    .split(",")
    .map((value) => value.trim().toUpperCase())
    .filter(Boolean);
  return new Set(values.length ? values : ["ES"]);
}

function envBool(value, fallback = false) {
  if (value == null || value === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

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

function compactPolicy(decision) {
  const policy = decision?.policyBaseline || {};
  return {
    final_decision: policy.finalDecision || "unknown",
    would_block: !!policy.wouldBlock,
    decision_stage: policy.decisionStage || "unknown",
    reason: policy.reason || null,
    early_rules: compactEarly(decision?.early),
    device_gate: compactGate(decision?.deviceGate),
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

async function monitorSessionSchemaReady(db) {
  if (!db) return false;
  try {
    const row = await db
      .prepare(
        `SELECT COUNT(*) AS n
         FROM sqlite_master
         WHERE type = 'table'
           AND name = 'adaptive_live_capture_sessions'`
      )
      .first();
    return Number(row?.n || 0) === 1;
  } catch {
    return false;
  }
}

async function registerMonitorSession(db, payload) {
  await db
    .prepare(
      `INSERT INTO adaptive_live_capture_sessions
       (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
       VALUES (?, ?, ?, NULL)`
    )
    .bind(payload.sid, Number(payload.iat), Number(payload.exp))
    .run();

  try {
    await db
      .prepare(
        `DELETE FROM adaptive_live_capture_sessions
         WHERE expires_at_ms < ?`
      )
      .bind(Date.now() - 86_400_000)
      .run();
  } catch {}
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

async function healthWithMonitor(request, env, ctx) {
  const response = await m21Worker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const sessionReady = await monitorSessionSchemaReady(env.DB);
  return Response.json(
    {
      ...data,
      m22_version: VERSION,
      m22_phase: "public-traffic-shadow-monitor",
      m22_public_monitor_ready:
        !!env.CHALLENGE_SECRET && sessionReady && (await adaptiveSchemaReady(env.DB)),
      m22_public_monitor_path: "/check",
      m22_telegram_bound: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID,
      m22_deep_inspection_after_policy_block: true,
      m22_dataset_eligible: false,
      m22_enforcing: false,
      m22_raw_ip_stored: false,
      m22_user_agent_stored: false,
      m22_raw_telemetry_stored: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function handleMonitorPage(request, env, ctx) {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (!env.CHALLENGE_SECRET) {
    return new Response("Monitor unavailable: challenge secret missing.", { status: 503 });
  }
  if (!(await monitorSessionSchemaReady(env.DB))) {
    return new Response("Monitor unavailable: session schema missing.", { status: 503 });
  }

  const issued = await issueMonitorToken(
    env.CHALLENGE_SECRET,
    Number(env.PROBE_TOKEN_TTL_MS || 90000)
  );
  await registerMonitorSession(env.DB, issued.payload);

  const network = networkInfo(request);
  const ua = request.headers.get("user-agent") || "";
  const early = evaluateV63EarlyRules({
    path: "/",
    ua,
    network,
    allowedCountries: allowedCountries(env),
    humansOnly: envBool(env.HUMANS_ONLY, true),
  });

  const hitMessage = buildTelegramHitMessage({
    sessionId: issued.payload.sid,
    network,
    early,
    uaFamily: coarseUaFamily(ua),
  });
  waitUntil(ctx, sendTelegram(env, hitMessage));

  return new Response(monitorBrowserProbeHtml(issued.token), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

async function handleMonitorSubmit(request, env, ctx) {
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
  const policyBaseline = compactPolicy(decision);

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
      decision.monitorDeepInspection ? "continued_after_policy_block" : "normal_detection_path",
      ...(decision.finalReasons || []),
    ],
    telemetrySummary: {
      mode: "shadow",
      baseline: BASELINE,
      source: "public_traffic_monitor",
      scope: "live",
      dataset_eligible: false,
      training_eligible: false,
      monitor_deep_inspection: !!decision.monitorDeepInspection,
      policy_baseline: policyBaseline,
      sanitized_feature_summary: sanitizeLiveFeatureSummary({ ua, telemetry }),
      decision_stage: decision.decisionStage,
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

  const finalMessage = buildTelegramDecisionMessage({
    sessionId: tokenPayload.sid,
    network,
    decision,
    v7,
    fingerprint: decision.fingerprint,
    policyBaseline: decision.policyBaseline,
    monitorDeepInspection: decision.monitorDeepInspection,
  });
  waitUntil(ctx, sendTelegram(env, finalMessage));

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
      policy_baseline: policyBaseline,
      monitor_deep_inspection: !!decision.monitorDeepInspection,
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
      return healthWithMonitor(request, env, ctx);
    }
    if (url.pathname === "/check" || url.pathname === "/check/") {
      return handleMonitorPage(request, env, ctx);
    }
    if (url.pathname === "/_shadow/v7-monitor-submit") {
      return handleMonitorSubmit(request, env, ctx);
    }

    return m21Worker.fetch(request, env, ctx);
  },
};
