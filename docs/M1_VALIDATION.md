# M1 V6.3 Compatibility Shadow — Validation Record

Status: **VALIDATED IN SHADOW**

This document records validation of the V6.3 compatibility layer on branch `m1-v63-compat`.

## Scope validated

- V6.3 early-rule order: honeypot -> country -> hard ASN -> verified bot -> strong automation UA.
- MOBILE_ONLY device gate.
- `scoreSignals()` local risk and spoof scoring.
- Temporary V6.3 fingerprint reputation window (30 minutes; 5/8 network thresholds).
- Workers AI `confidence_v2` first-pass classifier.
- Dual-review critic conditions.
- Full V6.3 shadow orchestrator order.
- D1 + R2 shadow persistence for sanitized observations.
- No enforcement in M1.
- Synthetic/admin observations excluded from training.
- No raw IP, raw User-Agent, or raw telemetry persisted.

## Real-device validation

A real iPhone on an ES network reached the full V6.3 shadow path and produced:

- early rules: continue
- device gate: mobile pass
- local risk: 0
- spoof signals: 0
- strong hardware spoof: false
- fingerprint state stored with no reputation penalty
- AI1: allow / `human_mobile`
- human probability: 95
- final decision: allow

The real-device test exposed a false positive in the M1 browser probe's font collection. The probe had used `document.fonts.check()`, which could report Windows fonts on Safari due to fallback behavior. The probe was corrected to use the V6.3 canvas-width `measureText()` method, and the same real iPhone subsequently returned local risk 0 with the false-positive reason removed.

## Full spoof-path validation

Synthetic ES mobile-spoof profile through the full orchestrator produced:

- early rules: continue
- device gate: mobile pass
- local risk: 100
- spoof signals: 14
- strong hardware spoof: true
- decision stage: `local_hard_block`
- AI1 logging pass: block / `desktop_emulation`
- spoof probability: 99
- final decision: block

`critic_run=false` on this path is expected: once the local hard-block threshold is reached, V6.3 may run AI1 only for hard-block logging when `AI_LOG_ON_HARD_BLOCK=true`; the critic is not required for the already-final local hard block.

## Storage validation

Validated shadow writes to D1 and R2 under test-only prefixes, including `tests/browser/full/...`.

All validated test events retained:

- `dataset_eligible: false`
- `raw_ip_stored: false`
- `user_agent_stored: false`
- `raw_telemetry_stored: false`

## Guardrails

- This validation does **not** authorize enforcement.
- This validation does **not** modify V6.3 production.
- PR #3 remains unmerged until the V7 transition plan explicitly calls for it.
- `main` remains separate from the M1 branch work.

## Next phase

Begin V7 Adaptive Learning on top of the validated V6.3 shadow baseline:

1. D1-backed adaptive reputation signals.
2. Explicit feedback labels and outcome correction.
3. Shadow comparison: V6.3 verdict vs V7 adaptive verdict.
4. Dataset eligibility rules for real observations.
5. Only after sufficient validation: controlled enforcement experiments.
