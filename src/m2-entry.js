import m1Worker from "./m1-full-entry.js";
import { networkInfo } from "./engine/network.js";
import { deriveAdaptiveFingerprintId } from "./adaptive/fingerprint-id.js";
import {
  ADAPTIVE_LABELS,
  computeV7ShadowDecision,
  decayStoredReputation,
} from "./adaptive/reputation.js";
import {
  adaptiveSchemaReady,
  getAdaptiveEventContext,
  getAdaptiveFeedbackForEvent,
  getAdaptiveReputations,
  insertAdaptiveFeedback,
  insertAdaptiveShadowObservation,
  rebuildAdaptiveReputation,
  recordAdaptiveObservationEntities,
} from "./storage/adaptive-d1.js";

const M2_VERSION = "V7.0_M2_SHADOW";
const M2_PHASE = "m2-adaptive-reputation";

function adminAuthorized(request, env) {
  const direct = request.headers.get("x-admin-secret") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ")
    ? auth.slice(7).trim()
    : "";
  const supplied = direct || bearer;
  return !!env.ADMIN_SECRET && supplied === env.ADMIN_SECRET;
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

function applyReadDecay(reputations, nowMs = Date.now()) {
  const asnDecay = decayStoredReputation(reputations?.asn, {
    entityType: "asn",
    nowMs,
    lastFeedbackAt: reputations?.asn?.lastFeedbackAt || null,
  });
  const fpDecay = decayStoredReputation(reputations?.fingerprint, {
    entityType: "fingerprint",
    nowMs,
    lastFeedbackAt: reputations?.fingerprint?.lastFeedbackAt || null,
  });

  return {
    asn: {
      ...(reputations?.asn || {}),
      ...asnDecay,
    },
    fingerprint: {
      ...(reputations?.fingerprint || {}),
      ...fpDecay,
    },
  };
}

async function healthWithM2(request, env, ctx) {
  const response = await m1Worker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const schemaReady = await adaptiveSchemaReady(env.DB);
  return Response.json(
    {
      ...data,
      adaptive_version: M2_VERSION,
      adaptive_phase: M2_PHASE,
      v7_adaptive_code_ready: true,
      v7_adaptive_schema_ready: schemaReady,
      v7_adaptive_feedback_ready: schemaReady,
      v7_shadow_comparison_ready: schemaReady,
      adaptive_reputation_scope_isolation: ["test", "live"],
      adaptive_training_from_ai_decisions: false,
      adaptive_decay: {
        asn_half_life_days: 30,
        fingerprint_half_life_days: 14,
      },
    },
    {
      status: response.status,
      headers: { "cache-control": "no-store" },
    }
  );
}

async function parseProbeTelemetry(request) {
  try {
    const body = await request.json();
    return body?.telemetry && typeof body.telemetry === "object"
      ? body.telemetry
      : {};
  } catch {
    return {};
  }
}

async function handleAdaptiveBrowserSubmit(request, env, ctx) {
  const inspectionRequest = request.clone();
  const telemetryPromise = parseProbeTelemetry(inspectionRequest);
  const ua = request.headers.get("user-agent") || "";
  const network = networkInfo(request);

  // M1 remains the decision/storage authority for this endpoint.
  const m1Response = await m1Worker.fetch(request, env, ctx);

  let m1Data;
  try {
    m1Data = await m1Response.clone().json();
  } catch {
    return m1Response;
  }

  if (
    !m1Response.ok ||
    !m1Data?.event_id ||
    !String(m1Data?.status || "").startsWith("v63_full_shadow_decision_")
  ) {
    return m1Response;
  }

  const telemetry = await telemetryPromise;
  const datasetEligible = m1Data.dataset_eligible === true;
  const scope = datasetEligible ? "live" : "test";

  try {
    if (!(await adaptiveSchemaReady(env.DB))) {
      return Response.json(
        {
          ...m1Data,
          adaptive_version: M2_VERSION,
          v7_shadow: {
            ready: false,
            reason: "adaptive_schema_not_ready",
            migration: "0003_v7_adaptive_reputation.sql",
          },
        },
        { status: m1Response.status }
      );
    }

    const fingerprintId = await deriveAdaptiveFingerprintId(
      env.CHALLENGE_SECRET,
      { ua, telemetry }
    );
    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();

    await recordAdaptiveObservationEntities(env.DB, {
      scope,
      asn: network.asn || null,
      fingerprintId,
      nowIso,
    });

    const storedReputations = await getAdaptiveReputations(env.DB, {
      scope,
      asn: network.asn || null,
      fingerprintId,
    });
    const reputations = applyReadDecay(storedReputations, nowMs);

    const v7 = computeV7ShadowDecision({
      v63Decision: m1Data.final_decision || "unknown",
      decisionStage: m1Data.decision_stage || "post_ai",
      localRisk: Number(m1Data.local?.risk || 0),
      ai1: m1Data.ai?.ai1 || null,
      ai2: m1Data.ai?.ai2 || null,
      asnReputation: reputations.asn,
      fingerprintReputation: reputations.fingerprint,
    });

    await insertAdaptiveShadowObservation(env.DB, {
      eventId: m1Data.event_id,
      scope,
      asn: network.asn || null,
      fingerprintId,
      v63Decision: m1Data.final_decision || "unknown",
      v63Risk: Number(m1Data.local?.risk || 0),
      v7,
      asnReputation: reputations.asn,
      fingerprintReputation: reputations.fingerprint,
      datasetEligible,
      nowIso,
    });

    return Response.json(
      {
        ...m1Data,
        adaptive_version: M2_VERSION,
        adaptive_phase: M2_PHASE,
        v7_shadow: {
          ready: true,
          enforcing: false,
          scope,
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
          raw_ip_stored: false,
          user_agent_stored: false,
          raw_telemetry_stored: false,
          ai_decision_used_as_training_label: false,
        },
      },
      { status: m1Response.status }
    );
  } catch (error) {
    return Response.json(
      {
        ...m1Data,
        adaptive_version: M2_VERSION,
        v7_shadow: {
          ready: false,
          reason: "adaptive_runtime_error",
          error: String(error?.message || error).slice(0, 240),
        },
      },
      { status: m1Response.status }
    );
  }
}

function validateFeedbackSemantics(label, v63Decision) {
  if (label === "false_positive" && v63Decision !== "block") {
    return "false_positive_requires_v63_block";
  }
  if (label === "false_negative" && v63Decision !== "allow") {
    return "false_negative_requires_v63_allow";
  }
  return null;
}

async function handleFeedback(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!adminAuthorized(request, env)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!(await adaptiveSchemaReady(env.DB))) {
    return Response.json(
      { error: "adaptive_schema_not_ready", migration: "0003_v7_adaptive_reputation.sql" },
      { status: 503 }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }

  const eventId = String(body?.event_id || "").trim();
  const label = String(body?.label || "").trim();
  const confidence = Math.max(
    0,
    Math.min(100, Number.isFinite(Number(body?.confidence)) ? Math.round(Number(body.confidence)) : 100)
  );
  const notes = body?.notes == null
    ? null
    : String(body.notes).trim().slice(0, 300) || null;

  if (!eventId) return Response.json({ error: "event_id_required" }, { status: 400 });
  if (!ADAPTIVE_LABELS.has(label)) {
    return Response.json(
      { error: "invalid_label", allowed_labels: [...ADAPTIVE_LABELS] },
      { status: 400 }
    );
  }

  const context = await getAdaptiveEventContext(env.DB, eventId);
  if (!context) return Response.json({ error: "event_not_found" }, { status: 404 });

  const semanticError = validateFeedbackSemantics(label, context.v63Decision);
  if (semanticError) {
    return Response.json({ error: semanticError }, { status: 400 });
  }

  const existing = await getAdaptiveFeedbackForEvent(env.DB, eventId);
  if (existing) {
    return Response.json(
      {
        error: "feedback_already_exists",
        event_id: eventId,
        existing_label: existing.label,
      },
      { status: 409 }
    );
  }

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();

  try {
    await insertAdaptiveFeedback(env.DB, {
      eventId,
      scope: context.scope,
      label,
      confidence,
      notes,
      asn: context.asn,
      fingerprintId: context.fingerprintId,
      v63Decision: context.v63Decision,
      trainingEligible: context.datasetEligible,
      nowIso,
    });
  } catch (error) {
    if (/unique|constraint/i.test(String(error?.message || error))) {
      return Response.json({ error: "feedback_already_exists" }, { status: 409 });
    }
    throw error;
  }

  const asnReputation = context.asn
    ? await rebuildAdaptiveReputation(env.DB, {
        scope: context.scope,
        entityType: "asn",
        entityId: context.asn,
        nowMs,
      })
    : null;

  const fingerprintReputation = context.fingerprintId
    ? await rebuildAdaptiveReputation(env.DB, {
        scope: context.scope,
        entityType: "fingerprint",
        entityId: context.fingerprintId,
        nowMs,
      })
    : null;

  return Response.json(
    {
      status: "v7_feedback_recorded",
      adaptive_version: M2_VERSION,
      enforcing: false,
      event_id: eventId,
      scope: context.scope,
      label,
      confidence,
      v63_decision: context.v63Decision,
      training_eligible: context.datasetEligible,
      affects_live_reputation: context.scope === "live",
      asn_reputation: asnReputation,
      fingerprint_reputation: fingerprintReputation,
      historical_prediction_rewritten: false,
      raw_ip_stored: false,
      user_agent_stored: false,
    },
    { status: 201 }
  );
}

async function handleReputationLookup(request, env) {
  if (request.method !== "GET") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!adminAuthorized(request, env)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!(await adaptiveSchemaReady(env.DB))) {
    return Response.json({ error: "adaptive_schema_not_ready" }, { status: 503 });
  }

  const url = new URL(request.url);
  const eventId = String(url.searchParams.get("event_id") || "").trim();
  if (!eventId) return Response.json({ error: "event_id_required" }, { status: 400 });

  const context = await getAdaptiveEventContext(env.DB, eventId);
  if (!context) return Response.json({ error: "event_not_found" }, { status: 404 });

  const storedReputations = await getAdaptiveReputations(env.DB, {
    scope: context.scope,
    asn: context.asn,
    fingerprintId: context.fingerprintId,
  });
  const reputations = applyReadDecay(storedReputations);
  const feedback = await getAdaptiveFeedbackForEvent(env.DB, eventId);

  return Response.json({
    status: "v7_reputation_lookup",
    adaptive_version: M2_VERSION,
    event_id: eventId,
    scope: context.scope,
    v63_decision: context.v63Decision,
    has_feedback: !!feedback,
    feedback: feedback
      ? {
          label: feedback.label,
          confidence: Number(feedback.confidence || 0),
          source: feedback.source,
          training_eligible: feedback.training_eligible === 1,
          created_at: feedback.created_at,
        }
      : null,
    asn_reputation: compactReputation(reputations.asn, "asn"),
    fingerprint_reputation: compactReputation(
      reputations.fingerprint,
      "fingerprintId"
    ),
    raw_ip_stored: false,
    user_agent_stored: false,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return healthWithM2(request, env, ctx);
    }

    if (url.pathname === "/_shadow/browser-probe-submit") {
      return handleAdaptiveBrowserSubmit(request, env, ctx);
    }

    if (url.pathname === "/_shadow/v7-feedback") {
      return handleFeedback(request, env);
    }

    if (url.pathname === "/_shadow/v7-reputation") {
      return handleReputationLookup(request, env);
    }

    return m1Worker.fetch(request, env, ctx);
  },
};
