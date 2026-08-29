# M2.1 Live Shadow Data Pipeline

Status: **LIVE SHADOW VALIDATED / DO NOT MERGE**

Branch: `m2-1-live-shadow`

Base: validated M2 adaptive reputation branch `m2-adaptive-reputation`.

M2.1 does not enable enforcement. V6.3 remains the decision authority and V7 remains shadow-only.

## Purpose

M2.1 adds a controlled path for real, dataset-eligible observations without turning ordinary public traffic into training data automatically.

A live capture must be explicitly initiated by an authenticated admin session. The resulting browser token is cryptographically separate from the M1/M2 test probe token and can be consumed only once.

## D1 migration

Applied and validated:

`migrations/0005_m21_live_capture.sql`

It adds `adaptive_live_capture_sessions`, containing only a random session id and timestamps. No IP, User-Agent, or telemetry is stored in this table.

Health validation confirmed:

- `m21_live_capture_code_ready:true`
- `m21_live_capture_schema_ready:true`
- `m21_live_capture_ready:true`
- `m21_live_capture_requires_admin_session:true`
- `m21_live_capture_one_time_tokens:true`
- `m21_live_feedback_label_sync_ready:true`
- `m21_enforcing:false`
- `m21_ai_decisions_are_training_labels:false`
- raw IP/User-Agent/full telemetry storage flags are `false`

## Endpoints

### `POST /_shadow/v7-live-session`

Admin-secret protected. Issues one short-lived, one-time live capture URL.

### `GET /_shadow/v7-live-probe?token=...`

Renders the browser probe only for a valid, unused M2.1 live token.

### `POST /_shadow/v7-live-submit`

Consumes the live token atomically, runs the validated V6.3 full shadow decision, stores a sanitized dataset-eligible event, evaluates V7 adaptive reputation in `scope=live`, and stores the V6.3-vs-V7 shadow comparison.

### `POST /_shadow/v7-feedback`

Existing explicit feedback semantics remain unchanged. For `scope=live` + `training_eligible=true`, M2.1 also writes the explicit truth label to R2 using a deterministic event-id key. Re-submitting an already-labeled event can repair an R2 label sync because the R2 key is idempotent.

## R2 dataset contract

Features/events:

`events/YYYY/MM/DD/<event_id>.json`

Truth labels:

`labels/YYYY/MM/DD/<event_id>.json`

Events and labels are joined by `event_id` later. AI/V6.3 predictions are never treated as truth labels.

## Sanitization

The live event stores only coarse feature buckets/classes, including:

- platform family
- coarse touch/hardware/memory buckets
- coarse screen class and DPR bucket
- pointer/hover booleans
- GPU vendor family, not raw renderer
- automation boolean
- capability booleans
- coarse interaction buckets

The live dataset does not store:

- raw IP
- raw User-Agent
- raw full telemetry
- raw GPU renderer
- exact screen dimensions
- timezone string
- adaptive fingerprint id in R2

The adaptive fingerprint remains a keyed pseudonymous D1 operational identifier only.

## Safety invariants

- `enforcing:false`
- V6.3 remains decision authority
- live capture requires explicit admin-issued session
- live token type is separate from test token type
- live token is one-time-use
- test/live reputation scopes remain isolated
- AI/V6.3 decisions are observations, never truth labels
- no automatic labeling
- no ordinary traffic is silently promoted to dataset-eligible by this branch

## Real live validation — first observation

Controlled real mobile live capture produced event:

`3fcbeff7-23b1-479a-b19f-e8f02e219011`

Observed properties:

- `scope:live`
- `dataset_eligible:true`
- `token_consumed:true`
- D1 event write: success
- R2 event write: success
- R2 key: `events/2026/08/29/3fcbeff7-23b1-479a-b19f-e8f02e219011.json`
- adaptive shadow observation: success
- V6.3 decision: `allow`
- decision stage: `post_ai`
- local risk: `0`
- spoof signals: `0`
- V7 base risk: `5`
- neutral live ASN reputation: `50`
- neutral live fingerprint reputation: `50`
- V7 decision: `allow`
- V7 risk: `5`
- comparison: `same`
- reason: `neutral_reputation_mirrors_v63`
- no raw IP, User-Agent, or full telemetry stored
- AI decision was not used as a truth label

This validates the neutral live path: a real dataset-eligible event is stored and V7 mirrors V6.3 before explicit feedback exists.

## Explicit live truth label validation

The first live event was explicitly labeled:

- label: `human_confirmed`
- confidence: `100`
- `training_eligible:true`
- `affects_live_reputation:true`
- ASN reputation: `50 -> 60`
- fingerprint reputation: `50 -> 60`
- historical prediction rewritten: `false`
- notes stored: `false`
- R2 label sync attempted: `true`
- R2 label write: `true`
- R2 label key: `labels/2026/08/29/3fcbeff7-23b1-479a-b19f-e8f02e219011.json`

This validates the explicit truth-label path:

`real live event -> explicit feedback -> live reputation update -> R2 truth label`

## Real live validation — subsequent adaptive effect

A second controlled live capture from the same browser/device context produced event:

`dbc25137-bde0-424b-ab0d-5940470134d5`

Observed properties:

- `scope:live`
- `dataset_eligible:true`
- `token_consumed:true`
- D1 write: success
- R2 event write: success
- R2 key: `events/2026/08/29/dbc25137-bde0-424b-ab0d-5940470134d5.json`
- adaptive observation write: success
- V6.3 decision: `allow`
- local risk: `0`
- V7 base risk: `5`
- ASN reputation: approximately `60`, feedback count `1`, observation count `2`
- fingerprint reputation: approximately `60`, feedback count `1`, observation count `2`
- ASN adjustment: `0`
- fingerprint adjustment: `-1`
- V7 risk: `4`
- V7 decision: `allow`
- comparison: `same`
- reason includes `fingerprint_reputation:-1`
- no raw IP/User-Agent/full telemetry stored
- AI decision was not used as a truth label

This validates the complete live learning loop:

`REAL EVENT -> EXPLICIT TRUTH LABEL -> LIVE REPUTATION -> NEXT REAL EVENT -> ADAPTIVE RISK EFFECT`

The expected time decay is visible in the weights (`~0.9999`) and does not indicate instability.

The second observation also exercised the V6.3 critic path: the first classifier result had zero classification confidence, so the critic ran and returned a clean `allow / human_mobile` result at confidence 90. The final V6.3 decision remained `allow`; this is recorded as an observed shadow-path behavior, not as training truth.

## Checkpoint conclusion

**M2.1 Live Shadow Data Pipeline validation checkpoint passed for the implemented controlled live pipeline.**

Validated end-to-end behavior:

`admin-issued live session -> one-time live submission -> sanitized D1/R2 event -> V6.3 decision -> V7 live shadow comparison -> explicit truth label -> live reputation -> R2 label -> subsequent adaptive effect`

M2.1 remains:

- shadow-only
- `enforcing:false`
- stacked on validated M2
- isolated from production V6.3
- not approved for merge or enforcement

## Remaining before any future promotion decision

- Accumulate a substantially larger set of explicitly labeled real live events.
- Measure false-positive/false-negative rates and V6.3-vs-V7 disagreement rates.
- Validate hostile real-world labels only when ground truth is known; never manufacture hostile labels on real humans.
- Monitor fingerprint stability across browser/device/network changes.
- Define minimum evidence requirements before adaptive reputation can materially influence a future enforcement experiment.
- Define rollback and promotion criteria before any merge or enforcement discussion.
