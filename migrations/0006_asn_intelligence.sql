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
