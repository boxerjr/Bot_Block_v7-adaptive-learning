-- V7 Community Intelligence
-- Stores only shared ASN-level intelligence. No raw IP, UA, fingerprint,
-- telemetry, event ID, or other per-user identifier is stored here.

CREATE TABLE IF NOT EXISTS community_asn_intelligence (
  asn TEXT PRIMARY KEY,
  tier TEXT NOT NULL CHECK (tier IN ('hard', 'risk')),
  source TEXT NOT NULL,
  reason TEXT,
  confidence INTEGER NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
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
