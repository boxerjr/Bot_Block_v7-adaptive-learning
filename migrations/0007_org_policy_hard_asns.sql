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
