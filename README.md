# V7 Adaptive Learning

Adaptive AI anti-bot system for Cloudflare Workers.

## Status

**V7.0 bootstrap / development**

The production baseline is V6.3 and must remain untouched until V7 reaches behavioral compatibility.

## Goals

- Preserve V6.3 detection behavior first.
- Add D1-backed history, reputation and feedback.
- Store large anonymized training events in R2.
- Add contributor / installation trust before public telemetry intake.
- Train adaptive models only after sufficient labeled data exists.

## Planned architecture

- `src/engine/` — V6.3-compatible detection, risk and AI logic
- `src/adaptive/` — events, reputation and feedback
- `src/storage/` — D1 and R2 access
- `migrations/` — D1 schema
- `legacy/` — immutable V6.3 reference
- `docs/` — project documentation

## Required secrets

Never commit secret values.

- `CHALLENGE_SECRET`
- `ADMIN_SECRET`
- `TELEGRAM_TOKEN`
- `TELEGRAM_CHAT_ID`

Set them with Wrangler secrets or in the Cloudflare dashboard.

## Next milestone

**V7.0-M1: V6.3 compatibility**

Port V6.3 into modules without changing its decisions, then compare V6.3 and V7 against the same captured test cases before enabling adaptive reputation.
