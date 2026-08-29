# V7 Architecture

## Rule 1 — V6.3 remains the stable production fallback

V7 must first reach behavioral compatibility before adaptive features influence decisions.

## Data split

### D1
Use for:
- installations
- feedback labels
- ASN reputation
- fingerprint reputation
- model metadata
- recent / queryable event metadata

### R2
Use for:
- large anonymized event archives
- future training datasets
- model artifacts

## Privacy baseline

Public datasets must not contain:
- raw IP addresses
- secret tokens
- persistent raw identifiers
- full unfiltered browser telemetry unless explicitly reviewed and sanitized

## Anti-poisoning principle

Global feedback must never be trusted equally by default.
Every contributing installation needs:
- identity
- rate limits
- trust score
- contribution weighting
- anomaly / poisoning detection

## M1 preview policy

The `m1-v63-compat` branch is preview-only until V6.3 compatibility tests pass. Non-production builds must use the version-upload path and must not promote M1 code to production.
