const HARD_ORG_CLASSES = new Set(["hosting_cloud", "vpn_proxy"]);

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
      CREATE TABLE IF NOT EXISTS org_policy_hard_asns (
        asn TEXT PRIMARY KEY,
        org_class TEXT NOT NULL,
        matched_rule TEXT,
        reason TEXT NOT NULL,
        first_seen_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_org_policy_hard_asns_updated
        ON org_policy_hard_asns(updated_at_ms);
    `);
    return true;
  } catch {
    return false;
  }
}

export function orgHardBlockEnabled(env) {
  return boolEnv(env?.ORG_HARD_BLOCK_ENABLED, true);
}

export function organizationRequiresHardBlock(env, profile = {}) {
  if (!orgHardBlockEnabled(env)) return false;
  const classification = String(profile?.class || "");
  const confidence = Number(profile?.confidence || 0);
  return HARD_ORG_CLASSES.has(classification) && confidence >= 90;
}

export async function getOrgPromotedHardAsn(env, asnValue) {
  const asn = normalizeAsn(asnValue);
  if (!asn || !orgHardBlockEnabled(env) || !env?.DB) return null;
  if (!(await ensureSchema(env.DB))) return null;

  try {
    const row = await env.DB
      .prepare(
        `SELECT asn, org_class, matched_rule, reason, first_seen_ms, updated_at_ms
         FROM org_policy_hard_asns
         WHERE asn = ?
         LIMIT 1`
      )
      .bind(asn)
      .first();

    if (!row) return null;
    return {
      asn,
      tier: "hard",
      source: "org_policy_auto",
      reason: row.reason || "organization_policy_hard_asn",
      hardBlock: true,
      orgClass: row.org_class || null,
      matchedRule: row.matched_rule || null,
      firstSeenMs: Number(row.first_seen_ms || 0),
      updatedAtMs: Number(row.updated_at_ms || 0),
    };
  } catch {
    return null;
  }
}

export async function promoteOrgAsnToHard(env, asnValue, profile = {}, nowMs = Date.now()) {
  const asn = normalizeAsn(asnValue);
  if (!asn) return { promoted: false, reason: "asn_unavailable" };
  if (!organizationRequiresHardBlock(env, profile)) {
    return { promoted: false, reason: "organization_not_hard_policy" };
  }
  if (!env?.DB) return { promoted: false, reason: "db_unavailable" };
  if (!(await ensureSchema(env.DB))) return { promoted: false, reason: "schema_unavailable" };

  const orgClass = String(profile.class || "unknown").slice(0, 40);
  const matchedRule = String(profile.matchedRule || "none").slice(0, 80);
  const reason = orgClass === "vpn_proxy"
    ? "organization_vpn_proxy_hard_policy"
    : "organization_hosting_cloud_hard_policy";

  try {
    await env.DB
      .prepare(
        `INSERT INTO org_policy_hard_asns
         (asn, org_class, matched_rule, reason, first_seen_ms, updated_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(asn) DO UPDATE SET
           org_class = excluded.org_class,
           matched_rule = excluded.matched_rule,
           reason = excluded.reason,
           updated_at_ms = excluded.updated_at_ms`
      )
      .bind(asn, orgClass, matchedRule, reason, nowMs, nowMs)
      .run();

    return {
      promoted: true,
      asn,
      tier: "hard",
      source: "org_policy_auto",
      reason,
      hardBlock: true,
      orgClass,
      matchedRule,
    };
  } catch (error) {
    return {
      promoted: false,
      reason: "write_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}

export async function getOrgHardPolicyHealth(env) {
  const result = {
    enabled: orgHardBlockEnabled(env),
    promotedAsnCount: 0,
  };
  if (!env?.DB || !result.enabled) return result;
  if (!(await ensureSchema(env.DB))) return result;

  try {
    const row = await env.DB
      .prepare(`SELECT COUNT(*) AS n FROM org_policy_hard_asns`)
      .first();
    result.promotedAsnCount = Number(row?.n || 0);
  } catch {}
  return result;
}
