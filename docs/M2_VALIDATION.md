# M2 Adaptive Reputation — Shadow Validation Checkpoint

Status: **SHADOW VALIDATED / DO NOT MERGE YET**

Branch: `m2-adaptive-reputation`

Baseline decision authority: `V6.3_SILENT_AI` via the validated M1 shadow pipeline.

M2 remains **non-enforcing**. This checkpoint validates the implemented adaptive-reputation mechanics; it does **not** authorize production enforcement or replacement of V6.3.

## Safety invariants validated

- `enforcing:false` throughout M2 tests.
- Reputation scope isolation: `test` and `live` are separate.
- Synthetic/browser test observations are `dataset_eligible:false`.
- Synthetic feedback does not affect live reputation.
- AI/V6.3 decisions are observations only and are not used as training truth labels.
- No raw IP, raw User-Agent, or raw full telemetry is persisted by the adaptive path.
- Historical shadow predictions are not rewritten after feedback.
- Feedback notes are sanitized in the Worker and D1 hardening migration `0004_adaptive_feedback_hardening.sql` is active.

## Health checkpoint

Validated health flags:

- `v7_adaptive_code_ready:true`
- `v7_adaptive_schema_ready:true`
- `v7_adaptive_feedback_ready:true`
- `v7_shadow_comparison_ready:true`
- `v7_synthetic_learning_fixture_ready:true`
- `adaptive_feedback_notes_sanitized_in_worker:true`
- `adaptive_feedback_hardening_ready:true`
- `adaptive_training_from_ai_decisions:false`

Decay configuration:

- ASN half-life: 30 days
- fingerprint half-life: 14 days

## Real human-path adaptive validation

A real iPhone/ES shadow path was validated with clean V6.3 behavior:

- V6.3 final decision: `allow`
- base AI risk: `5`
- local risk: `0`
- no spoof signals
- no hard-local block

Initial adaptive state was neutral:

- ASN reputation: `50`
- fingerprint reputation: `50`
- adaptive adjustments: `0 / 0`
- V7 mirrored V6.3 with reason `neutral_reputation_mirrors_v63`

After two explicit `human_confirmed` labels at confidence 100:

- ASN reputation: approximately `66.665`
- fingerprint reputation: approximately `66.663`
- ASN adjustment: `-1`
- fingerprint adjustment: `-2`
- V7 risk: `5 -> 2`
- V7 decision: `allow`
- comparison: `same`

This validates that confirmed human evidence lowers adaptive risk progressively rather than instantly whitelisting an entity.

## Synthetic hostile-path adaptive validation

The hostile-learning fixture is intentionally isolated from real users:

- scope: `test`
- reserved private-use test ASN: `AS64512`
- synthetic fingerprint
- `dataset_eligible:false`
- `affects_live_reputation:false`
- simulated V6.3 decision: `allow`
- base risk: `45`

Observed progression with explicit `bot_confirmed` labels at confidence 100:

| Hostile labels | Reputation (approx.) | ASN adj. | FP adj. | V7 risk | V7 decision | Comparison |
|---:|---:|---:|---:|---:|---|---|
| 0 | 50.000 | 0 | 0 | 45 | allow | same |
| 1 | 40.000 | 0 | +1 | 46 | allow | same |
| 2 | 33.334 | +1 | +2 | 48 | allow | same |
| 3 | 28.572 | +2 | +4 | 51 | review | different |

Final decisive synthetic observation:

- V6.3 fixture decision: `allow`
- V7 decision: `review`
- V7 risk: `51`
- comparison: `different`
- ASN adjustment: `+2`
- fingerprint adjustment: `+4`
- reason includes `adaptive_risk_review`

This validates that hostile feedback progressively raises risk and can create a controlled V7-vs-V6.3 shadow disagreement without enforcement.

## Checkpoint conclusion

**M2 Adaptive Reputation shadow validation checkpoint passed for the implemented adaptive-learning pipeline.**

Validated end-to-end behavior:

`explicit feedback -> decayed reputation -> next observation -> adaptive risk adjustment -> V7 shadow comparison`

Both directions are demonstrated:

- `human_confirmed -> reputation up -> risk down`
- `bot_confirmed -> reputation down -> risk up`

No automatic training from AI/V6.3 decisions was introduced, and no live enforcement was enabled.

## Remaining before any merge/enforcement decision

- Keep PR/branch shadow-only.
- Do not merge M2 into `main` solely because this checkpoint passed.
- Build and validate the real `live` observation/feedback pipeline separately from synthetic/test fixtures.
- Accumulate enough labeled real-world observations to measure false-positive/false-negative behavior, calibration, drift, and disagreement rates.
- Define explicit promotion/rollback criteria before any future enforcement experiment.
