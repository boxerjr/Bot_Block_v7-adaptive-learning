# V7 Adaptive Learning

Adaptive AI anti-bot and traffic policy system for Cloudflare Workers.

## Status

**V7.0 production launch candidate**

The validated M1 → M2 → M2.1 → M2.2 stack is integrated into `main`. V7 now includes policy enforcement for country, `MOBILE_ONLY`, exact-IP manual blocking, Telegram controls, adaptive reputation, and a fail-safe redirect engine.

The historical V6.3 production deployment is not modified by this repository.

## Enforcement order

1. Country policy (`ALLOWED_COUNTRIES`) — blocked traffic goes to `BLOCK_URL` when redirects are configured; otherwise HTTP 404.
2. `MOBILE_ONLY=true` — obvious desktop traffic goes to `BLOCK_URL`; otherwise HTTP 404.
3. Exact-IP manual Telegram block — goes to `BLOCK_URL`; otherwise HTTP 404.
4. Allowed browser traffic runs the browser probe, fingerprint checks, local signals, Workers AI, and V7 adaptive comparison.
5. Confirmed human traffic redirects to `ORIGIN_URL`.
6. Bot, crawler, spoof, review, or adaptive V7 block/review redirects to `BLOCK_URL`.

The redirect engine has a loop guard and refuses to activate unless both targets are valid HTTPS URLs.

## Privacy and learning

Public monitor traffic is operational observation only:

- D1 operational observations: enabled
- R2 public-training writes: disabled
- `dataset_eligible=false`
- `training_eligible=false`
- no automatic truth labels from AI/V6.3/V7 decisions
- no raw IP, raw User-Agent, or raw full telemetry persisted

Exact-IP manual blocks use a keyed HMAC identifier rather than storing the raw IP.

Controlled dataset-eligible live captures and explicit feedback labels remain a separate admin-only path.

## Cloudflare bindings

Required bindings:

- Workers AI → `AI`
- D1 → `DB`
- R2 → `DATASET`

Required Cloudflare secrets:

- `CHALLENGE_SECRET`
- `ADMIN_SECRET`
- `TELEGRAM_TOKEN`
- `TELEGRAM_CHAT_ID`
- `ORIGIN_URL`
- `BLOCK_URL`

`ORIGIN_URL` and `BLOCK_URL` are intentionally not committed to this repository. Set them as Cloudflare secrets so a public GitHub repository does not disclose the redirect destinations.

Example:

```bash
npx wrangler secret put ORIGIN_URL
npx wrangler secret put BLOCK_URL
```

Never commit real secret values.

## Runtime configuration

Important defaults are in `wrangler.jsonc`:

- `ALLOWED_COUNTRIES=ES`
- `MOBILE_ONLY=true`
- `HUMANS_ONLY=true`
- `REDIRECT_ENFORCING=true`
- `RATE_LIMIT_PER_MIN=12`

`REDIRECT_ENFORCING=true` is fail-safe: if either redirect target is missing, invalid, non-HTTPS, or would create a same-origin loop, V7 does not redirect.

## Development

```bash
npm install
npm test
npx wrangler dev
```

Apply D1 migrations when provisioning a new environment:

```bash
npm run d1:migrate:remote
```

Deploy:

```bash
npm run deploy
```

## Repository layout

- `src/compat/v63/` — V6.3 compatibility logic
- `src/adaptive/` — reputation, feedback, fingerprints, monitor verdicts, Telegram controls, redirect policy
- `src/storage/` — D1/R2 storage
- `migrations/` — D1 schema
- `legacy/` — archived V6.3 reference
- `docs/` — validation checkpoints and architecture notes
- `test/` — regression tests

## Production health

`GET /_health` reports the active policy stack, Telegram readiness, rate limiting, manual-IP control, and redirect readiness. For redirect production readiness, verify:

```text
v7_redirect_requested: true
v7_redirect_enabled: true
v7_origin_url_configured: true
v7_block_url_configured: true
```

## Security

Do not open issues containing tokens, secrets, raw IP lists, private telemetry, or credentials. See `SECURITY.md`.
