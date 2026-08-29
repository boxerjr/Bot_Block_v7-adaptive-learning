-- V7 Adaptive Learning
-- Migration 0003: adaptive reputation, explicit feedback, and V6.3-vs-V7 shadow comparison
--
-- Safety properties:
-- - test and live reputation are isolated by scope
-- - no raw IP or raw User-Agent columns exist here
-- - fingerprint_id is a keyed pseudonymous identifier produced by the Worker
-- - model/AI decisions are observations, not truth labels
-- - free-text notes are automatically cleared to avoid accidental identifiers

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS adaptive_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL CHECK (scope IN ('test', 'live')),
  label TEXT NOT NULL CHECK (label IN (
    'human_confirmed',
    'bot_confirmed',
    'spoof_confirmed',
    'false_positive',
    'false_negative',
    'uncertain'
  )),
  confidence INTEGER NOT NULL DEFAULT 100 CHECK (confidence BETWEEN 0 AND 100),
  source TEXT NOT NULL DEFAULT 'manual_admin',
  notes TEXT,
  asn TEXT,
  fingerprint_id TEXT,
  v63_decision_at_label TEXT CHECK (v63_decision_at_label IN ('allow', 'block', 'review', 'unknown')),
  training_eligible INTEGER NOT NULL DEFAULT 0 CHECK (training_eligible IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_adaptive_feedback_scope_created
  ON adaptive_feedback(scope, created_at);
CREATE INDEX IF NOT EXISTS idx_adaptive_feedback_scope_asn
  ON adaptive_feedback(scope, asn, created_at);
CREATE INDEX IF NOT EXISTS idx_adaptive_feedback_scope_fp
  ON adaptive_feedback(scope, fingerprint_id, created_at);

CREATE TRIGGER IF NOT EXISTS trg_adaptive_feedback_clear_notes_insert
AFTER INSERT ON adaptive_feedback
WHEN NEW.notes IS NOT NULL
BEGIN
  UPDATE adaptive_feedback SET notes = NULL WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS trg_adaptive_feedback_clear_notes_update
AFTER UPDATE OF notes ON adaptive_feedback
WHEN NEW.notes IS NOT NULL
BEGIN
  UPDATE adaptive_feedback SET notes = NULL WHERE id = NEW.id;
END;

CREATE TABLE IF NOT EXISTS adaptive_asn_reputation (
  scope TEXT NOT NULL CHECK (scope IN ('test', 'live')),
  asn TEXT NOT NULL,
  reputation_score REAL NOT NULL DEFAULT 50 CHECK (reputation_score BETWEEN 0 AND 100),
  human_weight REAL NOT NULL DEFAULT 0,
  hostile_weight REAL NOT NULL DEFAULT 0,
  evidence_weight REAL NOT NULL DEFAULT 0,
  feedback_count INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT,
  last_feedback_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scope, asn)
);

CREATE INDEX IF NOT EXISTS idx_adaptive_asn_score
  ON adaptive_asn_reputation(scope, reputation_score);

CREATE TABLE IF NOT EXISTS adaptive_fingerprint_reputation (
  scope TEXT NOT NULL CHECK (scope IN ('test', 'live')),
  fingerprint_id TEXT NOT NULL,
  reputation_score REAL NOT NULL DEFAULT 50 CHECK (reputation_score BETWEEN 0 AND 100),
  human_weight REAL NOT NULL DEFAULT 0,
  hostile_weight REAL NOT NULL DEFAULT 0,
  evidence_weight REAL NOT NULL DEFAULT 0,
  feedback_count INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT,
  last_feedback_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scope, fingerprint_id)
);

CREATE INDEX IF NOT EXISTS idx_adaptive_fp_score
  ON adaptive_fingerprint_reputation(scope, reputation_score);

CREATE TABLE IF NOT EXISTS adaptive_shadow_observations (
  event_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('test', 'live')),
  asn TEXT,
  fingerprint_id TEXT,
  v63_decision TEXT NOT NULL CHECK (v63_decision IN ('allow', 'block', 'review', 'unknown')),
  v63_risk INTEGER NOT NULL DEFAULT 0 CHECK (v63_risk BETWEEN 0 AND 100),
  v7_decision TEXT NOT NULL CHECK (v7_decision IN ('allow', 'block', 'review')),
  v7_risk INTEGER NOT NULL DEFAULT 0 CHECK (v7_risk BETWEEN 0 AND 100),
  comparison TEXT NOT NULL CHECK (comparison IN ('same', 'different')),
  asn_reputation_score REAL,
  fingerprint_reputation_score REAL,
  asn_adjustment INTEGER NOT NULL DEFAULT 0,
  fingerprint_adjustment INTEGER NOT NULL DEFAULT 0,
  reasons_json TEXT,
  dataset_eligible INTEGER NOT NULL DEFAULT 0 CHECK (dataset_eligible IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (event_id) REFERENCES events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_adaptive_shadow_scope_created
  ON adaptive_shadow_observations(scope, created_at);
CREATE INDEX IF NOT EXISTS idx_adaptive_shadow_comparison
  ON adaptive_shadow_observations(scope, comparison, created_at);
