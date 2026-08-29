# M2.1 Live Shadow Data Pipeline

Status: **IMPLEMENTED / VALIDATION REQUIRED / DO NOT MERGE**

Branch: `m2-1-live-shadow`

Base: validated M2 adaptive reputation branch `m2-adaptive-reputation`.

M2.1 does not enable enforcement. V6.3 remains the decision authority and V7 remains shadow-only.

## Purpose

M2.1 adds a controlled path for real, dataset-eligible observations without turning ordinary public traffic into training data automatically.

A live capture must be explicitly initiated by an authenticated admin session. The resulting browser token is cryptographically separate from the M1/M2 test probe token and can be consumed only once.

## D1 migration

Apply:

`migrations/0005_m21_live_capture.sql`

It adds `adaptive_live_capture_sessions`, containing only a random session id and timestamps. No IP, User-Agent, or telemetry is stored in this table.

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

## Validation required

Before this branch is considered validated:

1. Apply migration `0005_m21_live_capture.sql` in the test Cloudflare D1 database.
2. Confirm `_health` reports `m21_live_capture_schema_ready:true` and `m21_live_capture_ready:true`.
3. Create one admin live-capture session and open it on a real ES mobile device.
4. Confirm the resulting event has `scope:live`, `dataset_eligible:true`, R2 key under `events/`, and no raw identifiers.
5. Confirm neutral live reputation mirrors V6.3.
6. Apply one explicit feedback label to that event.
7. Confirm the feedback affects only `live` reputation and creates an R2 key under `labels/`.
8. Confirm the one-time token cannot be submitted again.
9. Keep enforcement disabled.
