import m2Worker from "./m2-learning-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { deriveAdaptiveFingerprintId } from "./adaptive/fingerprint-id.js";
import {
  buildLiveLabelRecord,
  sanitizeLiveFeatureSummary,
} from "./adaptive/live-features.js";
import { liveBrowserProbeHtml } from "./adaptive/live-probe.js";
import {
  issueLiveCaptureToken,
  verifyLiveCaptureToken,
} from "./adaptive/live-token.js";
import {
  computeV7ShadowDecision,
  decayStoredReputation,
} from "./adaptive/reputation.js";
import { runV63FullShadowDecision } from "./compat/v63/full-shadow.js";
import {
  adaptiveSchemaReady,
  getAdaptiveEventContext,
  getAdaptiveFeedbackForEvent,
  getAdaptiveReputations,
  insertAdaptiveShadowObservation,
  recordAdaptiveObservationEntities,
} from "./storage/adaptive-d1.js";
import { insertEvent } from "./storage/d1.js";
import { writeDatasetObject } from "./storage/dataset.js";
import { writeLiveLabelObject } from "./storage/live-dataset.js";

const VERSION = "V7.0_M2_1_LIVE_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

function adminAuthorized(request, env) {
  const direct = request.headers.get("x-admin-secret") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ")
    ? auth.slice(7).trim()
    : "";
  return !!env.ADMIN_SECRET && (direct || bearer) === env.ADMIN_SECRET;
}

function compactReputation(rep, idName) {
  if (!rep) return null;
  return {
    [idName]: rep[idName] || null,
    reputation_score: Number(rep.reputationScore ?? 50),
    human_weight: Number(rep.humanWeight || 0),
    hostile_weight: Number(rep.hostileWeight || 0),
    evidence_weight: Number(rep.evidenceWeight || 0),
    feedback_count: Number(rep.feedbackCount || 0),
    observation_count: Number(rep.observationCount || 0),
  };
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

async function liveCaptureSchemaReady(db) {
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

async function registerLiveSession(db, payload) {
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

async function liveSessionUsable(db, sid, nowMs = Date.now()) {
  try {
    const row = await db
      .prepare(
        `SELECT sid, expires_at_ms, consumed_at_ms
         FROM adaptive_live_capture_sessions
         WHERE sid = ?`
      )
      .bind(sid)
      .first();
    return !!row && !row.consumed_at_ms && Number(row.expires_at_ms) > nowMs;
  } catch {
    return false;
  }
}

async function consumeLiveSession(db, sid, nowMs = Date.now()) {
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

async function healthWithM21(request, env, ctx) {
  const response = await m2Worker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const adaptiveReady = await adaptiveSchemaReady(env.DB);
  const liveReady = await liveCaptureSchemaReady(env.DB);

  return Response.json(
    {
      ...data,
      m21_version: VERSION,
      m21_phase: "live-shadow-data-pipeline",
      m21_live_capture_code_ready: true,
      m21_live_capture_schema_ready: liveReady,
      m21_live_capture_ready: adaptiveReady && liveReady,
      m21_live_capture_requires_admin_session: true,
      m21_live_capture_one_time_tokens: true,
      m21_live_dataset_events_prefix: "events/",
      m21_live_dataset_labels_prefix: "labels/",
      m21_live_feedback_label_sync_ready: true,
      m21_enforcing: false,
      m21_ai_decisions_are_training_labels: false,
      m21_raw_ip_stored: false,
      m21_user_agent_stored: false,
      m21_raw_telemetry_stored: false,
    },
    {
      status: response.status,
      headers: { "cache-control": "no-store" },
    }
  );
}

async function handleLiveSession(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!adminAuthorized(request, env)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!env.CHALLENGE_SECRET) {
    return Response.json({ error: "challenge_secret_missing" }, { status: 503 });
  }
  if (!(await adaptiveSchemaReady(env.DB)) || !(await liveCaptureSchemaReady(env.DB))) {
    return Response.json(
      { error: "m21_live_schema_not_ready", migration: "0005_m21_live_capture.sql" },
      { status: 503 }
    );
  }

  const issued = await issueLiveCaptureToken(
    env.CHALLENGE_SECRET,
    Number(env.PROBE_TOKEN_TTL_MS || 90000)
  );
  await registerLiveSession(env.DB, issued.payload);

  const probeUrl = new URL("/_shadow/v7-live-probe", request.url);
  probeUrl.searchParams.set("token", issued.token);

  return Response.json(
    {
      status: "m21_live_capture_session_issued",
      m21_version: VERSION,
      enforcing: false,
      dataset_eligible: true,
      scope: "live",
      one_time: true,
      expires_at_ms: Number(issued.payload.exp),
      probe_url: probeUrl.toString(),
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
    },
    { status: 201, headers: { "cache-control": "no-store" } }
  );
}

async function handleLiveProbePage(request, env) {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const token = new URL(request.url).searchParams.get("token") || "";
  const payload = await verifyLiveCaptureToken(env.CHALLENGE_SECRET, token);
  if (!payload || !(await liveSessionUsable(env.DB, payload.sid))) {
    return new Response("Invalid, expired, or already-used live capture session.", {
      status: 401,
      headers: { "cache-control": "no-store" },
    });
  }

  return new Response(liveBrowserProbeHtml(token), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

async function handleLiveSubmit(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!env.CHALLENGE_SECRET) {
    return Response.json({ error: "challenge_secret_missing" }, { status: 503 });
  }
  if (!(await adaptiveSchemaReady(env.DB)) || !(await liveCaptureSchemaReady(env.DB))) {
    return Response.json({ error: "m21_live_schema_not_ready" }, { status: 503 });
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

  const tokenPayload = await verifyLiveCaptureToken(
    env.CHALLENGE_SECRET,
    body?.token || ""
  );
  if (!tokenPayload) {
    return Response.json({ error: "invalid_or_expired_live_token" }, { status: 401 });
  }

  const consumed = await consumeLiveSession(env.DB, tokenPayload.sid);
  if (!consumed) {
    return Response.json({ error: "live_token_already_used_or_expired" }, { status: 409 });
  }

  const telemetry =
    body?.telemetry && typeof body.telemetry === "object" ? body.telemetry : {};
  const ua = request.headers.get("user-agent") || "";
  const network = networkInfo(request);
  const ip = clientIp(request);

  const decision = await runV63FullShadowDecision({
    request,
    env,
    network,
    ip,
    ua,
    telemetry,
    targetPath: "/",
  });

  const featureSummary = sanitizeLiveFeatureSummary({ ua, telemetry });
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
      "m21_live_dataset_capture",
      "v63_full_decision",
      ...(decision.finalReasons || []),
    ],
    telemetrySummary: {
      mode: "shadow",
      baseline: BASELINE,
      source: "real_browser_live_v63_shadow",
      dataset_eligible: true,
      scope: "live",
      label_status: "unlabeled",
      sanitized_feature_summary: featureSummary,
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
      fingerprint_hash_stored_in_dataset: false,
      ai_decision_used_as_training_label: false,
    },
  });

  try {
    await insertEvent(env.DB, event);
  } catch (error) {
    return Response.json(
      {
        error: "live_event_d1_write_failed",
        detail: String(error?.message || error).slice(0, 180),
        token_consumed: true,
      },
      { status: 500 }
    );
  }

  let r2Key = null;
  let r2Written = false;
  try {
    r2Key = await writeDatasetObject(env.DATASET, event, { prefix: "events" });
    r2Written = true;
  } catch {}

  let adaptiveWritten = false;
  let v7 = null;
  let reputations = null;

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
      datasetEligible: true,
      nowIso,
    });
    adaptiveWritten = true;
  } catch {}

  return Response.json(
    {
      status:
        r2Written && adaptiveWritten
          ? "m21_live_shadow_event_stored"
          : "m21_live_shadow_event_partial",
      m21_version: VERSION,
      baseline: BASELINE,
      enforcing: false,
      scope: "live",
      dataset_eligible: true,
      event_id: event.event_id,
      token_consumed: true,
      d1_written: true,
      r2_written: r2Written,
      r2_key: r2Key,
      adaptive_observation_written: adaptiveWritten,
      final_decision: decision.finalDecision,
      would_block: decision.finalDecision === "block",
      decision_stage: decision.decisionStage,
      final_reasons: decision.finalReasons,
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
            scope: "live",
            decision: v7.v7Decision,
            risk: v7.v7Risk,
            comparison: v7.comparison,
            base_risk: v7.baseRisk,
            asn_adjustment: v7.asnAdjustment,
            fingerprint_adjustment: v7.fingerprintAdjustment,
            reasons: v7.reasons,
            asn_reputation: compactReputation(reputations.asn, "asn"),
            fingerprint_reputation: compactReputation(
              reputations.fingerprint,
              "fingerprintId"
            ),
          }
        : { ready: false, reason: "adaptive_observation_write_failed" },
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      ai_decision_used_as_training_label: false,
    },
    { status: r2Written && adaptiveWritten ? 201 : 207 }
  );
}

async function syncLiveFeedbackLabel(request, env, ctx) {
  const inspection = request.clone();
  let requestedEventId = "";
  try {
    const body = await inspection.json();
    requestedEventId = String(body?.event_id || "").trim();
  } catch {}

  const response = await m2Worker.fetch(request, env, ctx);
  if (!requestedEventId || !env.DATASET || !env.DB) return response;

  let context;
  let feedback;
  try {
    context = await getAdaptiveEventContext(env.DB, requestedEventId);
    feedback = await getAdaptiveFeedbackForEvent(env.DB, requestedEventId);
  } catch {
    return response;
  }

  if (
    !context ||
    context.scope !== "live" ||
    context.datasetEligible !== true ||
    !feedback
  ) {
    return response;
  }

  const labelRecord = buildLiveLabelRecord({
    eventId: requestedEventId,
    label: feedback.label,
    confidence: Number(feedback.confidence || 0),
    createdAt: feedback.created_at || new Date().toISOString(),
  });

  let key = null;
  let written = false;
  try {
    key = await writeLiveLabelObject(env.DATASET, labelRecord);
    written = true;
  } catch {}

  try {
    const data = await response.clone().json();
    return Response.json(
      {
        ...data,
        live_label_r2_sync_attempted: true,
        live_label_r2_written: written,
        live_label_r2_key: key,
      },
      { status: response.status, headers: { "cache-control": "no-store" } }
    );
  } catch {
    return response;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return healthWithM21(request, env, ctx);
    }
    if (url.pathname === "/_shadow/v7-live-session") {
      return handleLiveSession(request, env);
    }
    if (url.pathname === "/_shadow/v7-live-probe") {
      return handleLiveProbePage(request, env);
    }
    if (url.pathname === "/_shadow/v7-live-submit") {
      return handleLiveSubmit(request, env);
    }
    if (url.pathname === "/_shadow/v7-feedback" && request.method === "POST") {
      return syncLiveFeedbackLabel(request, env, ctx);
    }

    return m2Worker.fetch(request, env, ctx);
  },
};
