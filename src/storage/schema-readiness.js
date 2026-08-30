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

const ADDITIVE_RELEASE_SCHEMA_STATEMENTS = Object.freeze([
  `CREATE TABLE IF NOT EXISTS asn_intelligence (
    asn TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    tier TEXT NOT NULL,
    reason TEXT,
    updated_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_asn_intelligence_expiry
    ON asn_intelligence(expires_at_ms)`,
  `CREATE TABLE IF NOT EXISTS asn_intelligence_meta (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at_ms INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS community_asn_intelligence (
    asn TEXT PRIMARY KEY,
    tier TEXT NOT NULL CHECK (tier IN ('hard', 'risk')),
    source TEXT NOT NULL,
    reason TEXT,
    confidence INTEGER NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    feedback_count INTEGER NOT NULL DEFAULT 0,
    feed_generated_at TEXT,
    updated_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_community_asn_expiry
    ON community_asn_intelligence(expires_at_ms)`,
  `CREATE TABLE IF NOT EXISTS community_intelligence_meta (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at_ms INTEGER NOT NULL
  )`,
]);

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

/**
 * Runtime bootstrap for migrations 0006 and 0007 only.
 *
 * These migrations are purely additive intelligence/cache tables with no data
 * transformation. Older foundational migrations (0001-0005) are deliberately
 * NOT created here: a genuinely fresh or broken installation must still run
 * Wrangler migrations and remain release-not-ready until it does.
 */
export async function ensureReleaseAdditiveSchema(db) {
  if (!db) return { ready: false, reason: "db_unavailable" };
  try {
    // Execute one DDL statement at a time. This is compatible with the remote
    // Worker D1 binding and avoids relying on multi-statement exec support.
    // Every statement is additive and idempotent, so concurrent cold starts
    // and partially completed retries are safe.
    if (typeof db.prepare === "function") {
      for (const statement of ADDITIVE_RELEASE_SCHEMA_STATEMENTS) {
        await db.prepare(statement).run();
      }
    } else if (typeof db.exec === "function") {
      // Retain compatibility with local/test D1 adapters that expose only
      // exec(), while production uses the statement-by-statement path above.
      await db.exec(`${ADDITIVE_RELEASE_SCHEMA_STATEMENTS.join(";\n")};`);
    } else {
      throw new Error("D1 schema execution unavailable");
    }
    return {
      ready: true,
      reason: "ok",
      bootstrappedMigrations: [
        "0006_asn_intelligence.sql",
        "0007_community_intelligence.sql",
      ],
    };
  } catch (error) {
    return {
      ready: false,
      reason: "additive_schema_bootstrap_failed",
      error: String(error?.message || error).slice(0, 160),
      bootstrappedMigrations: [],
    };
  }
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
      requiredMigrationCount: 7,
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
