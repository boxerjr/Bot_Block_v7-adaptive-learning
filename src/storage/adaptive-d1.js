import { computeReputationFromFeedback } from "../adaptive/reputation.js";

function neutralReputation(idKey, idValue) {
  return {
    [idKey]: idValue || null,
    reputationScore: 50,
    humanWeight: 0,
    hostileWeight: 0,
    evidenceWeight: 0,
    feedbackCount: 0,
    observationCount: 0,
  };
}

function normalizeReputationRow(row, idKey, idValue) {
  if (!row) return neutralReputation(idKey, idValue);
  return {
    [idKey]: row[idKey] || idValue || null,
    reputationScore: Number(row.reputation_score ?? 50),
    humanWeight: Number(row.human_weight || 0),
    hostileWeight: Number(row.hostile_weight || 0),
    evidenceWeight: Number(row.evidence_weight || 0),
    feedbackCount: Number(row.feedback_count || 0),
    observationCount: Number(row.observation_count || 0),
    lastSeenAt: row.last_seen_at || null,
    lastFeedbackAt: row.last_feedback_at || null,
    updatedAt: row.updated_at || null,
  };
}

export async function adaptiveSchemaReady(db) {
  if (!db) return false;
  try {
    const result = await db
      .prepare(
        `SELECT COUNT(*) AS n
         FROM sqlite_master
         WHERE type = 'table'
           AND name IN (
             'adaptive_feedback',
             'adaptive_asn_reputation',
             'adaptive_fingerprint_reputation',
             'adaptive_shadow_observations'
           )`
      )
      .first();
    return Number(result?.n || 0) === 4;
  } catch {
    return false;
  }
}

export async function recordAdaptiveObservationEntities(
  db,
  { scope, asn = null, fingerprintId = null, nowIso = new Date().toISOString() }
) {
  if (!db) return;

  const statements = [];

  if (asn) {
    statements.push(
      db
        .prepare(
          `INSERT INTO adaptive_asn_reputation
             (scope, asn, observation_count, first_seen_at, last_seen_at, updated_at)
           VALUES (?1, ?2, 1, ?3, ?3, ?3)
           ON CONFLICT(scope, asn) DO UPDATE SET
             observation_count = adaptive_asn_reputation.observation_count + 1,
             last_seen_at = excluded.last_seen_at,
             updated_at = excluded.updated_at`
        )
        .bind(scope, asn, nowIso)
    );
  }

  if (fingerprintId) {
    statements.push(
      db
        .prepare(
          `INSERT INTO adaptive_fingerprint_reputation
             (scope, fingerprint_id, observation_count, first_seen_at, last_seen_at, updated_at)
           VALUES (?1, ?2, 1, ?3, ?3, ?3)
           ON CONFLICT(scope, fingerprint_id) DO UPDATE SET
             observation_count = adaptive_fingerprint_reputation.observation_count + 1,
             last_seen_at = excluded.last_seen_at,
             updated_at = excluded.updated_at`
        )
        .bind(scope, fingerprintId, nowIso)
    );
  }

  if (statements.length) await db.batch(statements);
}

export async function getAdaptiveReputations(
  db,
  { scope, asn = null, fingerprintId = null }
) {
  let asnRow = null;
  let fpRow = null;

  if (db && asn) {
    asnRow = await db
      .prepare(
        `SELECT * FROM adaptive_asn_reputation
         WHERE scope = ?1 AND asn = ?2`
      )
      .bind(scope, asn)
      .first();
  }

  if (db && fingerprintId) {
    fpRow = await db
      .prepare(
        `SELECT * FROM adaptive_fingerprint_reputation
         WHERE scope = ?1 AND fingerprint_id = ?2`
      )
      .bind(scope, fingerprintId)
      .first();
  }

  return {
    asn: normalizeReputationRow(asnRow, "asn", asn),
    fingerprint: normalizeReputationRow(fpRow, "fingerprintId", fingerprintId),
  };
}

export async function insertAdaptiveShadowObservation(
  db,
  {
    eventId,
    scope,
    asn = null,
    fingerprintId = null,
    v63Decision,
    v63Risk,
    v7,
    asnReputation,
    fingerprintReputation,
    datasetEligible = false,
    nowIso = new Date().toISOString(),
  }
) {
  await db
    .prepare(
      `INSERT INTO adaptive_shadow_observations (
         event_id, scope, asn, fingerprint_id,
         v63_decision, v63_risk,
         v7_decision, v7_risk, comparison,
         asn_reputation_score, fingerprint_reputation_score,
         asn_adjustment, fingerprint_adjustment,
         reasons_json, dataset_eligible, created_at
       ) VALUES (
         ?1, ?2, ?3, ?4,
         ?5, ?6,
         ?7, ?8, ?9,
         ?10, ?11,
         ?12, ?13,
         ?14, ?15, ?16
       )
       ON CONFLICT(event_id) DO UPDATE SET
         v7_decision = excluded.v7_decision,
         v7_risk = excluded.v7_risk,
         comparison = excluded.comparison,
         asn_reputation_score = excluded.asn_reputation_score,
         fingerprint_reputation_score = excluded.fingerprint_reputation_score,
         asn_adjustment = excluded.asn_adjustment,
         fingerprint_adjustment = excluded.fingerprint_adjustment,
         reasons_json = excluded.reasons_json`
    )
    .bind(
      eventId,
      scope,
      asn,
      fingerprintId,
      v63Decision,
      Math.max(0, Math.min(100, Number(v63Risk) || 0)),
      v7.v7Decision,
      v7.v7Risk,
      v7.comparison,
      asnReputation?.reputationScore ?? 50,
      fingerprintReputation?.reputationScore ?? 50,
      v7.asnAdjustment || 0,
      v7.fingerprintAdjustment || 0,
      JSON.stringify(v7.reasons || []),
      datasetEligible ? 1 : 0,
      nowIso
    )
    .run();
}

export async function getAdaptiveEventContext(db, eventId) {
  if (!db || !eventId) return null;

  const row = await db
    .prepare(
      `SELECT
         e.event_id,
         e.asn,
         e.final_decision,
         e.telemetry_summary_json,
         a.scope AS adaptive_scope,
         a.fingerprint_id
       FROM events e
       LEFT JOIN adaptive_shadow_observations a ON a.event_id = e.event_id
       WHERE e.event_id = ?1`
    )
    .bind(eventId)
    .first();

  if (!row) return null;

  let summary = {};
  try {
    summary = JSON.parse(row.telemetry_summary_json || "{}");
  } catch {}

  const datasetEligible = summary?.dataset_eligible === true;
  return {
    eventId: row.event_id,
    asn: row.asn || null,
    v63Decision: row.final_decision || "unknown",
    fingerprintId: row.fingerprint_id || null,
    scope: row.adaptive_scope || (datasetEligible ? "live" : "test"),
    datasetEligible,
  };
}

export async function getAdaptiveFeedbackForEvent(db, eventId) {
  if (!db || !eventId) return null;
  return db
    .prepare(`SELECT * FROM adaptive_feedback WHERE event_id = ?1`)
    .bind(eventId)
    .first();
}

export async function insertAdaptiveFeedback(
  db,
  {
    eventId,
    scope,
    label,
    confidence,
    notes = null,
    asn = null,
    fingerprintId = null,
    v63Decision = "unknown",
    trainingEligible = false,
    nowIso = new Date().toISOString(),
  }
) {
  await db
    .prepare(
      `INSERT INTO adaptive_feedback (
         event_id, scope, label, confidence, source, notes,
         asn, fingerprint_id, v63_decision_at_label,
         training_eligible, created_at
       ) VALUES (?1, ?2, ?3, ?4, 'manual_admin', ?5, ?6, ?7, ?8, ?9, ?10)`
    )
    .bind(
      eventId,
      scope,
      label,
      confidence,
      notes,
      asn,
      fingerprintId,
      v63Decision,
      trainingEligible ? 1 : 0,
      nowIso
    )
    .run();
}

async function feedbackRowsForEntity(db, { scope, entityType, entityId }) {
  if (!entityId) return [];
  const column = entityType === "fingerprint" ? "fingerprint_id" : "asn";
  const result = await db
    .prepare(
      `SELECT label, confidence, created_at
       FROM adaptive_feedback
       WHERE scope = ?1 AND ${column} = ?2
       ORDER BY created_at DESC
       LIMIT 1000`
    )
    .bind(scope, entityId)
    .all();
  return Array.isArray(result?.results) ? result.results : [];
}

async function upsertReputationCache(
  db,
  { scope, entityType, entityId, reputation, nowIso }
) {
  if (!entityId) return;

  const table = entityType === "fingerprint"
    ? "adaptive_fingerprint_reputation"
    : "adaptive_asn_reputation";
  const idColumn = entityType === "fingerprint" ? "fingerprint_id" : "asn";

  await db
    .prepare(
      `INSERT INTO ${table} (
         scope, ${idColumn}, reputation_score,
         human_weight, hostile_weight, evidence_weight,
         feedback_count, first_seen_at, last_feedback_at, updated_at
       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?8)
       ON CONFLICT(scope, ${idColumn}) DO UPDATE SET
         reputation_score = excluded.reputation_score,
         human_weight = excluded.human_weight,
         hostile_weight = excluded.hostile_weight,
         evidence_weight = excluded.evidence_weight,
         feedback_count = excluded.feedback_count,
         last_feedback_at = excluded.last_feedback_at,
         updated_at = excluded.updated_at`
    )
    .bind(
      scope,
      entityId,
      reputation.reputationScore,
      reputation.humanWeight,
      reputation.hostileWeight,
      reputation.evidenceWeight,
      reputation.feedbackCount,
      nowIso
    )
    .run();
}

export async function rebuildAdaptiveReputation(
  db,
  { scope, entityType, entityId, nowMs = Date.now() }
) {
  if (!db || !entityId) return null;
  const rows = await feedbackRowsForEntity(db, { scope, entityType, entityId });
  const reputation = computeReputationFromFeedback(rows, { entityType, nowMs });
  const nowIso = new Date(nowMs).toISOString();
  await upsertReputationCache(db, {
    scope,
    entityType,
    entityId,
    reputation,
    nowIso,
  });
  return reputation;
}
