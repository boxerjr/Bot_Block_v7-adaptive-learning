-- V7 Adaptive Learning
-- Migration 0005: controlled M2.1 live-shadow capture sessions.
--
-- Safety properties:
-- - stores only a random session id and timestamps; no IP/UA/telemetry
-- - live capture tokens are one-time-use to avoid duplicate dataset events
-- - session issuance remains admin-gated in the Worker

CREATE TABLE IF NOT EXISTS adaptive_live_capture_sessions (
  sid TEXT PRIMARY KEY,
  issued_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_adaptive_live_capture_expiry
  ON adaptive_live_capture_sessions(expires_at_ms);

CREATE INDEX IF NOT EXISTS idx_adaptive_live_capture_unused
  ON adaptive_live_capture_sessions(consumed_at_ms, expires_at_ms);
