import m2Worker from "./m2-entry.js";
import { buildEvent } from "./adaptive/events.js";
import { deriveAdaptiveFingerprintId } from "./adaptive/fingerprint-id.js";
import { hostileLearningFixture } from "./adaptive/learning-fixture.js";
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

const VERSION = "V7.0_M2_SHADOW";

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

async function feedbackHardeningReady(db) {
  if (!db) return false;
  try {
    const row = await db
      .prepare(
        `SELECT COUNT(*) AS n
         FROM sqlite_master
         WHERE type = 'trigger'
           AND name IN (
             'trg_adaptive_feedback_clear_notes_insert',
             'trg_adaptive_feedback_clear_notes_update'
           )`
      )
      .first();
    return Number(row?.n || 0) === 2;
  } catch {
    return false;
  }
}

async function healthWithLearningHarness(request, env, ctx) {
  const response = await m2Worker.fetch(request, env, ctx);
  try {
    const data = await response.clone().json();
    return Response.json(
      {
        ...data,
        v7_synthetic_learning_fixture_ready: true,
        adaptive_feedback_notes_sanitized_in_worker: true,
        adaptive_feedback_hardening_ready: await feedbackHardeningReady(env.DB),
        adaptive_feedback_hardening_migration: "0004_adaptive_feedback_hardening.sql",
      },
      {
        status: response.status,
        headers: { "cache-control": "no-store" },
      }
    );
  } catch {
    return response;
  }
}

async function handleSanitizedFeedback(request, env, ctx) {
  if (request.method !== "POST") return m2Worker.fetch(request, env, ctx);

  let body;
  try {
    body = await request.clone().json();
  } catch {
    return m2Worker.fetch(request, env, ctx);
  }

  const headers = new Headers(request.headers);
  headers.delete("content-length");

  const sanitizedRequest = new Request(request.url, {
    method: "POST",
    headers,
    body: JSON.stringify({ ...body, notes: null }),
  });

  const response = await m2Worker.fetch(sanitizedRequest, env, ctx);
  try {
    const data = await response.clone().json();
    return Response.json(
      { ...data, notes_stored: false },
      { status: response.status, headers: { "cache-control": "no-store" } }
    );
  } catch {
    return response;
  }
}

async function handleSyntheticLearningFixture(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!adminAuthorized(request, env)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!env.CHALLENGE_SECRET) {
    return Response.json({ error: "challenge_secret_missing" }, { status: 503 });
  }
  if (!(await adaptiveSchemaReady(env.DB))) {
    return Response.json({ error: "adaptive_schema_not_ready" }, { status: 503 });
  }

  const fixture = hostileLearningFixture();
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const fingerprintId = await deriveAdaptiveFingerprintId(
    env.CHALLENGE_SECRET,
    { ua: fixture.ua, telemetry: fixture.telemetry }
  );

  const event = buildEvent({
    network: fixture.network,
    local: {
      risk: fixture.baseRisk,
      spoofSignals: 0,
      strongHardwareSpoof: false,
      reasons: ["synthetic_adaptive_learning_fixture"],
    },
    decision: fixture.v63Decision,
    finalReasons: [
      "shadow_only",
      "synthetic_adaptive_learning_fixture",
      "simulated_v63_baseline_for_learning_test",
    ],
    telemetrySummary: {
      mode: "shadow",
      source: "synthetic_adaptive_learning_fixture",
      dataset_eligible: false,
      synthetic: true,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
    },
  });

  await insertEvent(env.DB, event);
  await recordAdaptiveObservationEntities(env.DB, {
    scope: fixture.scope,
    asn: fixture.network.asn,
    fingerprintId,
    nowIso,
  });

  const storedReputations = await getAdaptiveReputations(env.DB, {
    scope: fixture.scope,
    asn: fixture.network.asn,
    fingerprintId,
  });
  const reputations = applyReadDecay(storedReputations, nowMs);

  const v7 = computeV7ShadowDecision({
    v63Decision: fixture.v63Decision,
    decisionStage: fixture.v63DecisionStage,
    localRisk: fixture.baseRisk,
    asnReputation: reputations.asn,
    fingerprintReputation: reputations.fingerprint,
  });

  await insertAdaptiveShadowObservation(env.DB, {
    eventId: event.event_id,
    scope: fixture.scope,
    asn: fixture.network.asn,
    fingerprintId,
    v63Decision: fixture.v63Decision,
    v63Risk: fixture.baseRisk,
    v7,
    asnReputation: reputations.asn,
    fingerprintReputation: reputations.fingerprint,
    datasetEligible: false,
    nowIso,
  });

  return Response.json(
    {
      status: "v7_synthetic_learning_observation_stored",
      adaptive_version: VERSION,
      enforcing: false,
      synthetic: true,
      dataset_eligible: false,
      event_id: event.event_id,
      scope: fixture.scope,
      reserved_test_asn: fixture.network.asn,
      v63_fixture: {
        simulated: true,
        decision: fixture.v63Decision,
        decision_stage: fixture.v63DecisionStage,
        base_risk: fixture.baseRisk,
      },
      v7_shadow: {
        decision: v7.v7Decision,
        risk: v7.v7Risk,
        comparison: v7.comparison,
        asn_adjustment: v7.asnAdjustment,
        fingerprint_adjustment: v7.fingerprintAdjustment,
        reasons: v7.reasons,
        asn_reputation: compactReputation(reputations.asn, "asn"),
        fingerprint_reputation: compactReputation(
          reputations.fingerprint,
          "fingerprintId"
        ),
      },
      training_eligible: false,
      affects_live_reputation: false,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
    },
    { status: 201 }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return healthWithLearningHarness(request, env, ctx);
    }

    if (url.pathname === "/_shadow/v7-feedback") {
      return handleSanitizedFeedback(request, env, ctx);
    }

    if (url.pathname === "/_shadow/v7-learning-fixture") {
      return handleSyntheticLearningFixture(request, env);
    }

    return m2Worker.fetch(request, env, ctx);
  },
};
