import {
  getAdaptiveEventContext,
  getAdaptiveFeedbackForEvent,
  insertAdaptiveFeedback,
  rebuildAdaptiveReputation,
} from "../storage/adaptive-d1.js";
import {
  clearOwnerConfirmation,
  getOwnerConfirmationState,
} from "./owner-learning-timeout.js";

function looksLikeEventId(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
    String(value || "")
  );
}

export function ownerLearningEnabled(env) {
  return String(env?.OWNER_LEARNING_MODE || "false").trim().toLowerCase() === "true";
}

export async function recordOwnerHumanConfirmed(db, eventId, nowMs = Date.now()) {
  if (!db || !looksLikeEventId(eventId)) {
    return { learned: false, reason: "event_unavailable" };
  }

  try {
    // New OWNER_LEARNING_MODE observations have a 3-minute confirmation row.
    // Once that deadline has passed, IT'S ME is no longer accepted even if the
    // once-per-minute timeout sweep has not fired yet.
    const confirmation = await getOwnerConfirmationState(db, eventId, nowMs);
    if (confirmation?.expired) {
      return {
        learned: false,
        reason: "confirmation_expired",
        deadlineMs: confirmation.deadlineMs,
      };
    }

    const context = await getAdaptiveEventContext(db, eventId);
    if (!context) return { learned: false, reason: "event_not_found" };

    // OWNER learning buttons are only shown on HUMAN_PASS. Keep the same
    // invariant at write time so an old/tampered callback cannot confirm a
    // V6.3 block as human truth.
    if (context.v63Decision !== "allow") {
      return { learned: false, reason: "original_decision_not_allow" };
    }

    const existing = await getAdaptiveFeedbackForEvent(db, eventId);
    if (existing) {
      if (existing.label === "human_confirmed") {
        await clearOwnerConfirmation(db, eventId);
      }
      return {
        learned: false,
        reason: "feedback_already_exists",
        label: existing.label || null,
      };
    }

    const nowIso = new Date(nowMs).toISOString();
    await insertAdaptiveFeedback(db, {
      eventId,
      scope: context.scope,
      label: "human_confirmed",
      confidence: 100,
      notes: null,
      asn: context.asn,
      fingerprintId: context.fingerprintId,
      v63Decision: context.v63Decision,
      // Public monitor events remain outside R2/training. Controlled M2.1
      // captures keep their pre-existing dataset eligibility.
      trainingEligible: context.datasetEligible === true,
      nowIso,
    });

    if (context.asn) {
      await rebuildAdaptiveReputation(db, {
        scope: context.scope,
        entityType: "asn",
        entityId: context.asn,
        nowMs,
      });
    }

    if (context.fingerprintId) {
      await rebuildAdaptiveReputation(db, {
        scope: context.scope,
        entityType: "fingerprint",
        entityId: context.fingerprintId,
        nowMs,
      });
    }

    await clearOwnerConfirmation(db, eventId);

    return {
      learned: true,
      label: "human_confirmed",
      scope: context.scope,
      trainingEligible: context.datasetEligible === true,
    };
  } catch (error) {
    if (/unique|constraint/i.test(String(error?.message || error))) {
      return { learned: false, reason: "feedback_already_exists" };
    }
    return {
      learned: false,
      reason: "learning_write_failed",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}
