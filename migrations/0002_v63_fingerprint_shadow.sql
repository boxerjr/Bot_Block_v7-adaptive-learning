-- V7 M1 compatibility state for V6.3 fingerprint reputation.
-- This is deliberately separate from fingerprint_reputation, which belongs
-- to the future adaptive/label-based reputation model.

CREATE TABLE IF NOT EXISTS v63_fingerprint_shadow_state (
  fingerprint_id TEXT PRIMARY KEY,
  network_hashes_json TEXT NOT NULL DEFAULT '[]',
  seen INTEGER NOT NULL DEFAULT 0,
  last_seen_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_v63_fp_shadow_expires
  ON v63_fingerprint_shadow_state(expires_at_ms);
