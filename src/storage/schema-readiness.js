const REQUIRED_TABLES = Object.freeze({
  installations: "0001_initial.sql",
  events: "0001_initial.sql",
  feedback: "0001_initial.sql",
  asn_reputation: "0001_initial.sql",
  fingerprint_reputation: "0001_initial.sql",
  model_versions: "0001_initial.sql",
  v63_fingerprint_shadow_state: "0002_v63_fingerprint_shadow.sql",
  adaptive_feedback: "0003_v7_adaptive_reputation.sql",
  adaptive_asn_reputation: "0003_v7_adaptive_reputation.sql",
  adaptive_fingerprint_reputation: "0003_v7_adaptive_reputation.sql",
  adaptive_shadow_observations: "0003_v7_adaptive_reputation.sql",
  adaptive_live_capture_sessions: "0005_m21_live_capture.sql",
  asn_intelligence: "0006_asn_intelligence.sql",
  asn_intelligence_meta: "0006_asn_intelligence.sql",
  community_asn_intelligence: "0007_community_intelligence.sql",
  community_intelligence_meta: "0007_community_intelligence.sql",
});

const REQUIRED_TRIGGERS = Object.freeze({
  trg_adaptive_feedback_clear_notes_insert: "0004_adaptive_feedback_hardening.sql",
  trg_adaptive_feedback_clear_notes_update: "0004_adaptive_feedback_hardening.sql",
});

function unique(values) {
  return [...new Set(values)];
}

async function sqliteObjects(db, type) {
  const result = await db
    .prepare(`SELECT name FROM sqlite_master WHERE type = ? ORDER BY name`)
    .bind(type)
    .all();
  const rows = Array.isArray(result?.results) ? result.results : [];
  return new Set(rows.map((row) => String(row?.name || "")).filter(Boolean));
}

export async function getReleaseSchemaHealth(db) {
  if (!db) {
    return {
      ready: false,
      reason: "db_unavailable",
      missingTables: Object.keys(REQUIRED_TABLES),
      missingTriggers: Object.keys(REQUIRED_TRIGGERS),
      missingMigrations: unique([
        ...Object.values(REQUIRED_TABLES),
        ...Object.values(REQUIRED_TRIGGERS),
      ]),
    };
  }

  try {
    const [tables, triggers] = await Promise.all([
      sqliteObjects(db, "table"),
      sqliteObjects(db, "trigger"),
    ]);

    const missingTables = Object.keys(REQUIRED_TABLES).filter((name) => !tables.has(name));
    const missingTriggers = Object.keys(REQUIRED_TRIGGERS).filter((name) => !triggers.has(name));
    const missingMigrations = unique([
      ...missingTables.map((name) => REQUIRED_TABLES[name]),
      ...missingTriggers.map((name) => REQUIRED_TRIGGERS[name]),
    ]);

    return {
      ready: missingTables.length === 0 && missingTriggers.length === 0,
      reason: missingTables.length || missingTriggers.length ? "schema_incomplete" : "ok",
      missingTables,
      missingTriggers,
      missingMigrations,
      requiredMigrationCount: 7,
    };
  } catch (error) {
    return {
      ready: false,
      reason: "schema_check_failed",
      error: String(error?.message || error).slice(0, 160),
      missingTables: [],
      missingTriggers: [],
      missingMigrations: [],
      requiredMigrationCount: 7,
    };
  }
}
