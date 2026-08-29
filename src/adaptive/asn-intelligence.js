import { HARD_ASNS, RISK_ASNS, SAFE_ASNS } from "../compat/v63/policy.js";

const SPAMHAUS_ASN_DROP_URL = "https://www.spamhaus.org/drop/asndrop.json";
const DEFAULT_REFRESH_MS = 24 * 60 * 60 * 1000;
const FEED_TTL_MS = 48 * 60 * 60 * 1000;

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

async function ensureSchema(db) {
  if (!db) return false;
  try {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS asn_intelligence (
        asn TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        tier TEXT NOT NULL,
        reason TEXT,
        updated_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_asn_intelligence_expiry
        ON asn_intelligence(expires_at_ms);
      CREATE TABLE IF NOT EXISTS asn_intelligence_meta (
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
      .prepare(`SELECT value FROM asn_intelligence_meta WHERE key = ? LIMIT 1`)
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
        `INSERT INTO asn_intelligence_meta (key, value, updated_at_ms)
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

function staticClassification(asn) {
  if (!asn) return { tier: "unknown", source: "none", reason: "asn_unavailable" };
  if (SAFE_ASNS.has(asn)) {
    return { tier: "safe", source: "v63_safe_asn", reason: "known_access_asn" };
  }
  if (HARD_ASNS.has(asn)) {
    return { tier: "hard", source: "v63_hard_asn", reason: "known_hosting_or_high_risk_asn" };
  }
  if (RISK_ASNS.has(asn)) {
    return { tier: "risk", source: "v63_risk_asn", reason: "known_risk_asn" };
  }
  return { tier: "unknown", source: "none", reason: "asn_not_seeded" };
}

export function asnHardBlockEnabled(env) {
  return boolEnv(env?.ASN_HARD_BLOCK_ENABLED, true);
}

export function spamhausAsnDropEnabled(env) {
  return boolEnv(env?.ASN_SPAMHAUS_DROP_ENABLED, true);
}

export function orgHardPromotionEnabled(env) {
  return boolEnv(env?.ORG_INFRASTRUCTURE_HARD_BLOCK_ENABLED, true);
}

export async function promoteAsnToHardFromOrganization(
  env,
  asnValue,
  organizationClass,
  organizationRule = "unknown",
  nowMs = Date.now()
) {
  if (!orgHardPromotionEnabled(env)) return { promoted: false, reason: "disabled" };
  if (!env?.DB) return { promoted: false, reason: "db_unavailable" };

  const asn = normalizeAsn(asnValue);
  if (!asn) return { promoted: false, reason: "asn_unavailable" };
  if (!["hosting_cloud", "vpn_proxy"].includes(String(organizationClass || ""))) {
    return { promoted: false, reason: "organization_not_hard_class" };
  }
  if (!(await ensureSchema(env.DB))) return { promoted: false, reason: "schema_unavailable" };

  const reason = `org_${String(organizationClass).slice(0, 40)}:${String(organizationRule || "unknown").slice(0, 80)}`;
  try {
    await env.DB
      .prepare(
        `INSERT INTO asn_intelligence
         (asn, source, tier, reason, updated_at_ms, expires_at_ms)
         VALUES (?, 'org_auto_hard', 'hard', ?, ?, NULL)
         ON CONFLICT(asn) DO UPDATE SET
           source = CASE
             WHEN asn_intelligence.source = 'spamhaus_asndrop' THEN asn_intelligence.source
             ELSE excluded.source
           END,
           tier = 'hard',
           reason = CASE
             WHEN asn_intelligence.source = 'spamhaus_asndrop' THEN asn_intelligence.reason
             ELSE excluded.reason
           END,
           updated_at_ms = excluded.updated_at_ms,
           expires_at_ms = CASE
             WHEN asn_intelligence.source = 'spamhaus_asndrop' THEN asn_intelligence.expires_at_ms
             ELSE NULL
           END`
      )
      .bind(asn, reason, nowMs)
      .run();

    return {
      promoted: true,
      asn,
      tier: "hard",
      source: "org_auto_hard",
      reason,
    };
  } catch (error) {
    return {
      promoted: false,
      reason: "write_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}

export async function classifyAsn(env, asnValue, nowMs = Date.now()) {
  const asn = normalizeAsn(asnValue);
  if (!asn) {
    return { asn: null, tier: "unknown", source: "none", reason: "asn_unavailable", hardBlock: false };
  }

  // Dynamic hard intelligence and Spamhaus both live in D1. Any active hard
  // row intentionally overrides static SAFE/RISK seeds.
  if (env?.DB) {
    try {
      const row = await env.DB
        .prepare(
          `SELECT source, tier, reason, expires_at_ms
           FROM asn_intelligence
           WHERE asn = ?
             AND (expires_at_ms IS NULL OR expires_at_ms > ?)
           LIMIT 1`
        )
        .bind(asn, nowMs)
        .first();
      if (row?.tier === "hard") {
        if (row.source !== "spamhaus_asndrop" || spamhausAsnDropEnabled(env)) {
          return {
            asn,
            tier: "hard",
            source: row.source || "dynamic_hard",
            reason: row.reason || "dynamic_hard_asn",
            hardBlock: asnHardBlockEnabled(env),
          };
        }
      }
    } catch {}
  }

  const seeded = staticClassification(asn);
  return {
    asn,
    ...seeded,
    hardBlock: asnHardBlockEnabled(env) && seeded.tier === "hard",
  };
}

function parseSpamhausJsonLines(text) {
  const entries = new Map();
  let metadata = null;

  for (const line of String(text || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let value;
    try {
      value = JSON.parse(trimmed);
    } catch {
      continue;
    }

    if (Number.isFinite(Number(value?.asn))) {
      const asn = normalizeAsn(String(value.asn));
      if (!asn) continue;
      entries.set(asn, {
        asn,
        domain: String(value?.domain || "").slice(0, 180),
        cc: String(value?.cc || "").slice(0, 8),
        asname: String(value?.asname || "").slice(0, 180),
      });
      continue;
    }

    if (value?.type || value?.timestamp || value?.copyright) metadata = value;
  }

  return { entries: [...entries.values()], metadata };
}

async function writeFeedEntries(db, entries, nowMs) {
  const expiresAtMs = nowMs + FEED_TTL_MS;
  const statements = entries.map((entry) =>
    db
      .prepare(
        `INSERT INTO asn_intelligence
         (asn, source, tier, reason, updated_at_ms, expires_at_ms)
         VALUES (?, 'spamhaus_asndrop', 'hard', 'spamhaus_asn_drop', ?, ?)
         ON CONFLICT(asn) DO UPDATE SET
           source = excluded.source,
           tier = excluded.tier,
           reason = excluded.reason,
           updated_at_ms = excluded.updated_at_ms,
           expires_at_ms = excluded.expires_at_ms`
      )
      .bind(entry.asn, nowMs, expiresAtMs)
  );

  for (let i = 0; i < statements.length; i += 80) {
    await db.batch(statements.slice(i, i + 80));
  }

  await db
    .prepare(
      `DELETE FROM asn_intelligence
       WHERE source = 'spamhaus_asndrop'
         AND updated_at_ms < ?`
    )
    .bind(nowMs)
    .run();
}

export async function refreshSpamhausAsnDrop(env, nowMs = Date.now()) {
  if (!spamhausAsnDropEnabled(env)) return { refreshed: false, reason: "disabled" };
  if (!env?.DB) return { refreshed: false, reason: "db_unavailable" };
  if (!(await ensureSchema(env.DB))) return { refreshed: false, reason: "schema_unavailable" };

  const nextRefreshMs = Number(await getMeta(env.DB, "spamhaus_asndrop_next_refresh_ms") || 0);
  if (nextRefreshMs > nowMs) {
    return { refreshed: false, reason: "not_due", nextRefreshMs };
  }

  await setMeta(env.DB, "spamhaus_asndrop_next_refresh_ms", nowMs + DEFAULT_REFRESH_MS, nowMs);

  let response;
  try {
    response = await fetch(SPAMHAUS_ASN_DROP_URL, {
      headers: {
        accept: "application/json,text/plain;q=0.9,*/*;q=0.1",
        "user-agent": "V7-Adaptive-Learning/1.0 Spamhaus-ASN-DROP",
      },
    });
  } catch (error) {
    return {
      refreshed: false,
      reason: "fetch_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }

  if (!response.ok) {
    return { refreshed: false, reason: "http_error", status: response.status };
  }

  let parsed;
  try {
    parsed = parseSpamhausJsonLines(await response.text());
  } catch (error) {
    return {
      refreshed: false,
      reason: "parse_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }

  if (parsed.entries.length < 10) {
    return { refreshed: false, reason: "feed_too_small", count: parsed.entries.length };
  }

  try {
    await writeFeedEntries(env.DB, parsed.entries, nowMs);
    await setMeta(env.DB, "spamhaus_asndrop_last_success_ms", nowMs, nowMs);
    await setMeta(env.DB, "spamhaus_asndrop_last_count", parsed.entries.length, nowMs);
    if (parsed.metadata?.timestamp != null) {
      await setMeta(env.DB, "spamhaus_asndrop_source_timestamp", parsed.metadata.timestamp, nowMs);
    }
    if (parsed.metadata?.copyright) {
      await setMeta(env.DB, "spamhaus_asndrop_copyright", parsed.metadata.copyright, nowMs);
    }
    if (parsed.metadata?.terms) {
      await setMeta(env.DB, "spamhaus_asndrop_terms", parsed.metadata.terms, nowMs);
    }
    return {
      refreshed: true,
      reason: "ok",
      count: parsed.entries.length,
      nextRefreshMs: nowMs + DEFAULT_REFRESH_MS,
    };
  } catch (error) {
    return {
      refreshed: false,
      reason: "write_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}

export async function getAsnIntelligenceHealth(env, nowMs = Date.now()) {
  const result = {
    hardBlockEnabled: asnHardBlockEnabled(env),
    spamhausEnabled: spamhausAsnDropEnabled(env),
    orgHardPromotionEnabled: orgHardPromotionEnabled(env),
    staticHardCount: HARD_ASNS.size,
    staticRiskCount: RISK_ASNS.size,
    staticSafeCount: SAFE_ASNS.size,
    spamhausCount: 0,
    orgAutoHardCount: 0,
    spamhausLastSuccessMs: null,
  };

  if (!env?.DB) return result;
  try {
    const spamhaus = await env.DB
      .prepare(
        `SELECT COUNT(*) AS n
         FROM asn_intelligence
         WHERE source = 'spamhaus_asndrop'
           AND (expires_at_ms IS NULL OR expires_at_ms > ?)`
      )
      .bind(nowMs)
      .first();
    result.spamhausCount = Number(spamhaus?.n || 0);

    const orgAuto = await env.DB
      .prepare(
        `SELECT COUNT(*) AS n
         FROM asn_intelligence
         WHERE source = 'org_auto_hard'
           AND tier = 'hard'`
      )
      .first();
    result.orgAutoHardCount = Number(orgAuto?.n || 0);

    const last = await getMeta(env.DB, "spamhaus_asndrop_last_success_ms");
    result.spamhausLastSuccessMs = last ? Number(last) : null;
  } catch {}
  return result;
}
