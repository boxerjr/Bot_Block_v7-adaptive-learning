const DEFAULT_UPSTREAM_URL =
  "https://raw.githubusercontent.com/boxerjr/v7-adaptive-learning/community-feed/community/intelligence.json";
const REFRESH_MS = 6 * 60 * 60 * 1000;
const FEED_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_FEED_ENTRIES = 10_000;

function boolEnv(value, fallback = false) {
  if (value == null || value === "") return fallback;
  return String(value).trim().toLowerCase() === "true";
}

function normalizeAsn(value) {
  const raw = String(value || "").trim().toUpperCase();
  if (/^AS\d+$/.test(raw)) return raw;
  if (/^\d+$/.test(raw)) return `AS${raw}`;
  return null;
}

function clean(value, max = 160) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, max);
}

function isoFromMs(value) {
  const n = Number(value || 0);
  return n > 0 ? new Date(n).toISOString() : null;
}

async function ensureSchema(db) {
  if (!db) return false;
  try {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS community_asn_intelligence (
        asn TEXT PRIMARY KEY,
        tier TEXT NOT NULL CHECK (tier IN ('hard', 'risk')),
        source TEXT NOT NULL,
        reason TEXT,
        confidence INTEGER NOT NULL DEFAULT 0,
        feedback_count INTEGER NOT NULL DEFAULT 0,
        feed_generated_at TEXT,
        updated_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_community_asn_expiry
        ON community_asn_intelligence(expires_at_ms);
      CREATE TABLE IF NOT EXISTS community_intelligence_meta (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at_ms INTEGER NOT NULL
      );
    `);
    return true;
  } catch {
    return false;
  }
}

async function getMeta(db, key) {
  try {
    const row = await db
      .prepare(`SELECT value FROM community_intelligence_meta WHERE key = ? LIMIT 1`)
      .bind(key)
      .first();
    return row?.value ?? null;
  } catch {
    return null;
  }
}

async function setMeta(db, key, value, nowMs) {
  try {
    await db
      .prepare(
        `INSERT INTO community_intelligence_meta (key, value, updated_at_ms)
         VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at_ms = excluded.updated_at_ms`
      )
      .bind(key, String(value ?? ""), nowMs)
      .run();
    return true;
  } catch {
    return false;
  }
}

export function communityExportEnabled(env = {}) {
  return boolEnv(env.COMMUNITY_INTEL_EXPORT_ENABLED, true);
}

export function communityUpstreamEnabled(env = {}) {
  return boolEnv(env.COMMUNITY_INTEL_ENABLED, true);
}

export function communityHardBlockEnabled(env = {}) {
  return boolEnv(env.COMMUNITY_INTEL_HARD_BLOCK_ENABLED, true);
}

export function communityUpstreamUrl(env = {}) {
  const configured = clean(env.COMMUNITY_INTEL_UPSTREAM_URL, 500);
  return configured || DEFAULT_UPSTREAM_URL;
}

export async function buildCommunityIntelligenceExport(env, nowMs = Date.now()) {
  if (!communityExportEnabled(env)) {
    return { ready: false, reason: "disabled" };
  }
  if (!env?.DB) return { ready: false, reason: "db_unavailable" };

  let hardRows = [];
  let riskRows = [];
  try {
    const hard = await env.DB
      .prepare(
        `SELECT asn, reason, updated_at_ms
         FROM asn_intelligence
         WHERE source = 'org_auto_hard'
           AND tier = 'hard'
         ORDER BY asn ASC
         LIMIT ?`
      )
      .bind(MAX_FEED_ENTRIES)
      .all();
    hardRows = hard?.results || [];
  } catch {}

  try {
    const risk = await env.DB
      .prepare(
        `SELECT asn, reputation_score, human_weight, hostile_weight,
                evidence_weight, feedback_count, last_feedback_at
         FROM adaptive_asn_reputation
         WHERE scope = 'live'
           AND feedback_count >= 8
           AND hostile_weight >= 6
           AND human_weight <= 0.25
           AND reputation_score <= 20
         ORDER BY hostile_weight DESC, feedback_count DESC
         LIMIT ?`
      )
      .bind(MAX_FEED_ENTRIES)
      .all();
    riskRows = risk?.results || [];
  } catch {}

  const hardAsns = hardRows
    .map((row) => {
      const asn = normalizeAsn(row.asn);
      if (!asn) return null;
      return {
        asn,
        tier: "hard",
        source: "v7_org_infrastructure",
        reason: clean(row.reason || "hosting_or_vpn_infrastructure", 120),
        confidence: 100,
        updated_at: isoFromMs(row.updated_at_ms),
      };
    })
    .filter(Boolean);

  const hardSet = new Set(hardAsns.map((entry) => entry.asn));
  const riskAsns = riskRows
    .map((row) => {
      const asn = normalizeAsn(row.asn);
      if (!asn || hardSet.has(asn)) return null;
      return {
        asn,
        tier: "risk",
        source: "v7_feedback_consensus",
        reason: "strong_aggregated_hostile_feedback",
        confidence: 90,
        feedback_count: Math.max(0, Number(row.feedback_count || 0)),
        reputation_score: Math.max(0, Math.min(100, Number(row.reputation_score || 50))),
        hostile_weight: Number(Number(row.hostile_weight || 0).toFixed(3)),
        human_weight: Number(Number(row.human_weight || 0).toFixed(3)),
        last_feedback_at: row.last_feedback_at || null,
      };
    })
    .filter(Boolean);

  return {
    ready: true,
    schema_version: 1,
    generated_at: new Date(nowMs).toISOString(),
    producer: "v7-adaptive-learning",
    privacy: {
      raw_ip: false,
      user_agent: false,
      fingerprint: false,
      telemetry: false,
      event_ids: false,
    },
    policy: {
      hard: "Only locally-derived hosting/VPN/proxy infrastructure promoted by deterministic V7 policy.",
      risk: "Minimum 8 live feedback labels, hostile_weight >= 6, human_weight <= 0.25 and reputation_score <= 20. Feedback consensus is never promoted to global HARD by itself.",
      redistributed_external_feeds: false,
    },
    hard_asns: hardAsns,
    risk_asns: riskAsns,
  };
}

function parseCommunityFeed(value) {
  if (!value || Number(value.schema_version) !== 1) return null;
  const hard = Array.isArray(value.hard_asns) ? value.hard_asns : [];
  const risk = Array.isArray(value.risk_asns) ? value.risk_asns : [];
  if (hard.length + risk.length > MAX_FEED_ENTRIES * 2) return null;

  const entries = new Map();
  for (const raw of hard) {
    const asn = normalizeAsn(raw?.asn);
    if (!asn) continue;
    if (String(raw?.source || "") !== "v7_org_infrastructure") continue;
    entries.set(asn, {
      asn,
      tier: "hard",
      source: "community_repo",
      reason: clean(raw?.reason || "community_hosting_or_vpn", 120),
      confidence: Math.max(0, Math.min(100, Number(raw?.confidence || 100))),
      feedbackCount: 0,
    });
  }

  for (const raw of risk) {
    const asn = normalizeAsn(raw?.asn);
    if (!asn || entries.has(asn)) continue;
    if (String(raw?.source || "") !== "v7_feedback_consensus") continue;
    const feedbackCount = Math.max(0, Number(raw?.feedback_count || 0));
    const hostileWeight = Math.max(0, Number(raw?.hostile_weight || 0));
    const humanWeight = Math.max(0, Number(raw?.human_weight || 0));
    const score = Math.max(0, Math.min(100, Number(raw?.reputation_score || 50)));
    if (feedbackCount < 8 || hostileWeight < 6 || humanWeight > 0.25 || score > 20) continue;
    entries.set(asn, {
      asn,
      tier: "risk",
      source: "community_repo",
      reason: "community_feedback_consensus",
      confidence: Math.max(0, Math.min(100, Number(raw?.confidence || 90))),
      feedbackCount,
    });
  }

  return {
    generatedAt: clean(value.generated_at, 64) || null,
    entries: [...entries.values()],
  };
}

async function writeCommunityEntries(db, parsed, nowMs) {
  const expiresAtMs = nowMs + FEED_TTL_MS;
  const statements = parsed.entries.map((entry) =>
    db
      .prepare(
        `INSERT INTO community_asn_intelligence
         (asn, tier, source, reason, confidence, feedback_count,
          feed_generated_at, updated_at_ms, expires_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(asn) DO UPDATE SET
           tier = excluded.tier,
           source = excluded.source,
           reason = excluded.reason,
           confidence = excluded.confidence,
           feedback_count = excluded.feedback_count,
           feed_generated_at = excluded.feed_generated_at,
           updated_at_ms = excluded.updated_at_ms,
           expires_at_ms = excluded.expires_at_ms`
      )
      .bind(
        entry.asn,
        entry.tier,
        entry.source,
        entry.reason,
        entry.confidence,
        entry.feedbackCount,
        parsed.generatedAt,
        nowMs,
        expiresAtMs
      )
  );

  for (let i = 0; i < statements.length; i += 80) {
    await db.batch(statements.slice(i, i + 80));
  }

  await db
    .prepare(`DELETE FROM community_asn_intelligence WHERE updated_at_ms < ?`)
    .bind(nowMs)
    .run();
}

export async function refreshCommunityIntelligence(env, nowMs = Date.now()) {
  if (!communityUpstreamEnabled(env)) return { refreshed: false, reason: "disabled" };
  if (!env?.DB) return { refreshed: false, reason: "db_unavailable" };
  if (!(await ensureSchema(env.DB))) return { refreshed: false, reason: "schema_unavailable" };

  const nextRefreshMs = Number(await getMeta(env.DB, "next_refresh_ms") || 0);
  if (nextRefreshMs > nowMs) {
    return { refreshed: false, reason: "not_due", nextRefreshMs };
  }
  await setMeta(env.DB, "next_refresh_ms", nowMs + REFRESH_MS, nowMs);

  let response;
  try {
    response = await fetch(communityUpstreamUrl(env), {
      headers: {
        accept: "application/json",
        "user-agent": "V7-Adaptive-Learning/1.0 Community-Intel",
      },
    });
  } catch (error) {
    return {
      refreshed: false,
      reason: "fetch_failed",
      error: clean(error?.message || error, 120),
    };
  }

  if (!response.ok) return { refreshed: false, reason: "http_error", status: response.status };

  let parsed;
  try {
    parsed = parseCommunityFeed(await response.json());
  } catch {
    parsed = null;
  }
  if (!parsed) return { refreshed: false, reason: "invalid_feed" };

  try {
    await writeCommunityEntries(env.DB, parsed, nowMs);
    await setMeta(env.DB, "last_success_ms", nowMs, nowMs);
    await setMeta(env.DB, "last_count", parsed.entries.length, nowMs);
    return {
      refreshed: true,
      reason: "ok",
      count: parsed.entries.length,
      nextRefreshMs: nowMs + REFRESH_MS,
    };
  } catch (error) {
    return {
      refreshed: false,
      reason: "write_failed",
      error: clean(error?.message || error, 120),
    };
  }
}

export async function classifyCommunityAsn(env, asnValue, nowMs = Date.now()) {
  if (!communityUpstreamEnabled(env) || !env?.DB) return null;
  const asn = normalizeAsn(asnValue);
  if (!asn) return null;
  try {
    const row = await env.DB
      .prepare(
        `SELECT tier, source, reason, confidence, feedback_count
         FROM community_asn_intelligence
         WHERE asn = ? AND expires_at_ms > ?
         LIMIT 1`
      )
      .bind(asn, nowMs)
      .first();
    if (!row?.tier) return null;
    return {
      asn,
      tier: row.tier,
      source: row.source || "community_repo",
      reason: row.reason || "community_intelligence",
      confidence: Number(row.confidence || 0),
      feedbackCount: Number(row.feedback_count || 0),
      hardBlock: row.tier === "hard" && communityHardBlockEnabled(env),
    };
  } catch {
    return null;
  }
}

export async function getCommunityIntelligenceHealth(env, nowMs = Date.now()) {
  const result = {
    exportEnabled: communityExportEnabled(env),
    upstreamEnabled: communityUpstreamEnabled(env),
    hardBlockEnabled: communityHardBlockEnabled(env),
    upstreamUrl: communityUpstreamUrl(env),
    hardCount: 0,
    riskCount: 0,
    lastSuccessMs: null,
  };
  if (!env?.DB) return result;
  try {
    const hard = await env.DB
      .prepare(`SELECT COUNT(*) AS n FROM community_asn_intelligence WHERE tier = 'hard' AND expires_at_ms > ?`)
      .bind(nowMs)
      .first();
    const risk = await env.DB
      .prepare(`SELECT COUNT(*) AS n FROM community_asn_intelligence WHERE tier = 'risk' AND expires_at_ms > ?`)
      .bind(nowMs)
      .first();
    result.hardCount = Number(hard?.n || 0);
    result.riskCount = Number(risk?.n || 0);
    const last = await getMeta(env.DB, "last_success_ms");
    result.lastSuccessMs = last ? Number(last) : null;
  } catch {}
  return result;
}
