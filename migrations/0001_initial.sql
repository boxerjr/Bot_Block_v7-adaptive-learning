-- V7 Adaptive Learning
-- Migration 0001: initial adaptive-learning schema

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS installations (
  installation_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT,
  version TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  trust_score REAL NOT NULL DEFAULT 50 CHECK (trust_score >= 0 AND trust_score <= 100)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  installation_id TEXT,
  observed_at TEXT NOT NULL,
  country TEXT,
  asn TEXT,
  organization TEXT,
  local_risk INTEGER NOT NULL DEFAULT 0 CHECK (local_risk BETWEEN 0 AND 100),
  spoof_signals INTEGER NOT NULL DEFAULT 0,
  strong_hardware_spoof INTEGER NOT NULL DEFAULT 0 CHECK (strong_hardware_spoof IN (0, 1)),
  local_reasons_json TEXT,
  ai1_json TEXT,
  ai2_json TEXT,
  final_decision TEXT NOT NULL CHECK (final_decision IN ('allow', 'block', 'review', 'unknown')),
  final_reasons_json TEXT,
  telemetry_summary_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (installation_id) REFERENCES installations(installation_id)
);

CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
CREATE INDEX IF NOT EXISTS idx_events_asn_observed ON events(asn, observed_at);
CREATE INDEX IF NOT EXISTS idx_events_decision_observed ON events(final_decision, observed_at);

CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL,
  installation_id TEXT,
  label TEXT NOT NULL CHECK (label IN ('human', 'bot', 'spoof', 'uncertain')),
  confidence INTEGER NOT NULL DEFAULT 100 CHECK (confidence BETWEEN 0 AND 100),
  source TEXT NOT NULL DEFAULT 'manual',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (event_id) REFERENCES events(event_id),
  FOREIGN KEY (installation_id) REFERENCES installations(installation_id)
);

CREATE INDEX IF NOT EXISTS idx_feedback_event ON feedback(event_id);
CREATE INDEX IF NOT EXISTS idx_feedback_label_created ON feedback(label, created_at);

CREATE TABLE IF NOT EXISTS asn_reputation (
  asn TEXT PRIMARY KEY,
  human_count INTEGER NOT NULL DEFAULT 0,
  bot_count INTEGER NOT NULL DEFAULT 0,
  spoof_count INTEGER NOT NULL DEFAULT 0,
  uncertain_count INTEGER NOT NULL DEFAULT 0,
  reputation_score REAL NOT NULL DEFAULT 50 CHECK (reputation_score >= 0 AND reputation_score <= 100),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fingerprint_reputation (
  fingerprint_id TEXT PRIMARY KEY,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  observations INTEGER NOT NULL DEFAULT 0,
  human_count INTEGER NOT NULL DEFAULT 0,
  bot_count INTEGER NOT NULL DEFAULT 0,
  spoof_count INTEGER NOT NULL DEFAULT 0,
  reputation_score REAL NOT NULL DEFAULT 50 CHECK (reputation_score >= 0 AND reputation_score <= 100)
);

CREATE TABLE IF NOT EXISTS model_versions (
  model_version TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate', 'active', 'retired')),
  metrics_json TEXT,
  artifact_key TEXT,
  notes TEXT
);
