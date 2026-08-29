-- V7 Adaptive Learning
-- Migration 0004: harden adaptive feedback storage for deployments that applied 0003 before note scrubbing was added.
--
-- Idempotent: safe to apply whether or not these triggers already exist.

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

-- Scrub any historical note text that may have been written before the trigger existed.
UPDATE adaptive_feedback
SET notes = NULL
WHERE notes IS NOT NULL;
