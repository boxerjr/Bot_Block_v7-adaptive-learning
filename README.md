# V7 Adaptive Learning

**Adaptive AI anti-bot and traffic policy engine for Cloudflare Workers.**

V7 combines deterministic edge policy, browser/device consistency checks, Workers AI, adaptive D1 reputation, operator feedback, Telegram controls, ASN/organization intelligence, global honeypots, shared community intelligence, and privacy-preserving exact-IP state.

It is built for a strict policy: accept traffic consistent with a real person on a permitted consumer/mobile Internet connection and reject obvious hosting, VPN, proxy, scanner, automation, spoof, and policy-violating traffic as early as possible.

> V7 is not a claim of perfect bot detection. It is a layered enforcement and learning system designed to reduce obvious hostile traffic before expensive inspection, then improve decisions through explicit feedback and reputation.

## Current status

**V7 production stack — active development, production deployed.**

The historical V6.3 production deployment is intentionally separate and is not modified by this repository.

## What makes V7 different

V7 does not depend on one User-Agent regex or one AI answer. It uses several independent layers:

```text
exact-IP state
→ honeypot paths
→ shared Community HARD ASN
→ local/static/external ASN intelligence
→ organization intelligence
→ country policy
→ mobile/device policy
→ rate + browser consistency + fingerprint
→ Workers AI
→ adaptive D1 reputation
→ final redirect
```

The objective is simple: **do cheap deterministic checks first and spend browser/AI work only on traffic that survives them.**

## Major features

### Infrastructure intelligence

V7 classifies Cloudflare `asOrganization` metadata into classes such as:

```text
consumer_isp
mobile_carrier
hosting_cloud
vpn_proxy
unknown
```

Under the default strict policy:

```text
hosting_cloud → BLOCK + ASN promoted to HARD
vpn_proxy     → BLOCK + ASN promoted to HARD
consumer_isp  → continue inspection
mobile_carrier→ continue inspection
```

Known hosting/cloud examples include IONOS, DigitalOcean, OVH, Hetzner, Vultr, Linode, Leaseweb, Contabo, AWS, Google Cloud, Azure and Oracle Cloud.

Known Spanish access-network examples include Telefonica/Movistar, Digi, Orange, Vodafone, Jazztel, MasMovil, Euskaltel and others.

A real person using a VPN/VPS/cloud connection is intentionally denied when the strict infrastructure policy is enabled.

### ASN intelligence

V7 combines:

- V6.3 static `HARD_ASNS`, `RISK_ASNS`, and `SAFE_ASNS`
- dynamic `org_auto_hard` ASN promotion
- Spamhaus ASN-DROP operational intelligence
- V7 Community Intelligence

Hard infrastructure checks run before country and browser AI.

### Global honeypot gate

V7 keeps the 40-path V6.3 honeypot baseline and adds an extended scanner-path layer for targets such as:

```text
/.env
/.git/config
/.ssh/id_rsa
/wp-admin
/phpmyadmin
/secrets
/backup.zip
/actuator/env
/solr/admin
```

A matching request is deterministic hostile-path evidence:

```text
honeypot
→ AI skipped
→ exact IP HMAC block
→ BLOCK_URL or blank 404 fallback
```

Normal browser paths such as `/favicon.ico` and `/robots.txt` are not honeypots.

### Community Intelligence

Separate V7 deployments can share a privacy-safe ASN intelligence feed through this repository.

Shared `HARD` entries are restricted to V7-derived hosting/VPN/proxy infrastructure. Strong operator feedback can create shared `RISK` records only after strict consensus thresholds; feedback alone cannot globally hard-block an ASN.

The shared feed never contains:

```text
raw IP
raw User-Agent
fingerprint ID
browser telemetry
event ID
Telegram data
secrets
```

Third-party Spamhaus records are also excluded from the GitHub community export.

See [`docs/COMMUNITY_INTELLIGENCE.md`](docs/COMMUNITY_INTELLIGENCE.md).

### Browser and device inspection

Traffic that survives deterministic policy enters a silent browser inspection stage. V7 checks device/browser coherence, local spoof signals, fingerprint history and related browser evidence instead of trusting the User-Agent alone.

### Workers AI

Workers AI receives sanitized evidence plus network/organization context and produces classification/risk guidance.

**AI output never becomes a truth label by itself.**

### Adaptive D1 learning

Explicit feedback updates ASN and fingerprint reputation using labels including:

```text
human_confirmed
bot_confirmed
spoof_confirmed
false_positive
false_negative
uncertain
```

Evidence decays over time. Fingerprint evidence decays faster than ASN evidence.

This is immediate reputation learning — it is not retraining the Llama model after each click.

### Telegram controls

Standard operator controls:

```text
🚫 BLOCK IP
🔓 UNBLOCK IP
```

An operator block on an originally allowed event is recorded as a `false_negative` correction and rebuilds relevant reputation.

### Controlled OWNER learning

Default:

```text
OWNER_LEARNING_MODE=false
```

During an explicitly controlled owner-only session, `HUMAN_PASS` can expose:

```text
✅ IT'S ME
❌ NOT ME
```

`IT'S ME` records `human_confirmed` with confidence 100.

`NOT ME` records `false_negative` with confidence 100 and exact-IP blocks the request source.

If no `IT'S ME` confirmation arrives inside the three-minute deadline, the controlled pending event becomes automatic `NOT ME`. Keep this mode **off** during uncontrolled public traffic.

### Exact-IP privacy-preserving state

Manual and automatic exact-IP state uses a keyed HMAC identifier rather than a raw IP database column.

### Rate limiting

Default:

```text
RATE_LIMIT_PER_MIN=3
```

The fourth request inside the rolling window triggers an exact-IP automatic block. Unblocking also clears stale limiter state.

### Redirect enforcement

With `REDIRECT_ENFORCING=true`:

```text
confirmed human → ORIGIN_URL
blocked/review  → BLOCK_URL
```

Redirect destinations are Cloudflare secrets, must be HTTPS, and are protected by a loop guard.

If `BLOCK_URL` is unavailable, blocked traffic falls back to a blank 404 response.

## Privacy model

Ordinary public monitor traffic remains operational observation only:

```text
D1 operational observations: yes
R2 public training writes: no
dataset_eligible: false
training_eligible: false
AI decisions as truth labels: no
raw IP persistence: no
raw UA persistence: no
raw full telemetry persistence: no
```

Controlled dataset-eligible captures remain a separate admin path.

## Install on a new Cloudflare account

Start here:

**[`docs/INSTALL.md`](docs/INSTALL.md)**

The short version is:

```bash
git clone https://github.com/boxerjr/v7-adaptive-learning.git
cd v7-adaptive-learning
npm install
npx wrangler login
npx wrangler d1 create v7-adaptive-learning
npx wrangler r2 bucket create v7-adaptive-dataset
```

Then copy `wrangler.example.jsonc`, insert **your own** D1 database ID, configure the Cloudflare secrets, apply migrations, run tests and deploy:

```bash
npm run d1:migrate:remote
npm test
npm run deploy
```

Do not reuse another installation's D1 ID or secrets.

## Required Cloudflare bindings

```text
Workers AI → AI
D1         → DB
R2         → DATASET
```

## Cloudflare secrets

Core production secrets:

```text
CHALLENGE_SECRET
ADMIN_SECRET
ORIGIN_URL
BLOCK_URL
```

Telegram, when used:

```text
TELEGRAM_TOKEN
TELEGRAM_CHAT_ID
```

Example:

```bash
npx wrangler secret put CHALLENGE_SECRET
npx wrangler secret put ADMIN_SECRET
npx wrangler secret put ORIGIN_URL
npx wrangler secret put BLOCK_URL
```

Never commit real secret values.

## Important runtime defaults

Current strict defaults include:

```text
ALLOWED_COUNTRIES=ES
MOBILE_ONLY=true
HUMANS_ONLY=true
RATE_LIMIT_PER_MIN=3
REDIRECT_ENFORCING=true
OWNER_LEARNING_MODE=false
ASN_HARD_BLOCK_ENABLED=true
ASN_SPAMHAUS_DROP_ENABLED=true
ORG_INFRASTRUCTURE_HARD_BLOCK_ENABLED=true
HONEYPOT_ENFORCING=true
COMMUNITY_INTEL_EXPORT_ENABLED=true
COMMUNITY_INTEL_ENABLED=true
COMMUNITY_INTEL_HARD_BLOCK_ENABLED=true
```

See `wrangler.example.jsonc` for a reusable installation template.

## Community feed publishing

The Worker exposes a sanitized export at:

```text
/_community/intelligence.json
```

This repository contains an optional GitHub Actions publisher. Configure the repository secret:

```text
V7_COMMUNITY_FEED_URL
```

with the deployed export URL. Every six hours, the workflow validates the privacy/schema invariants and updates only:

```text
community-feed branch
└── community/intelligence.json
```

The data publisher never writes directly to protected production `main`.

## Full feature reference

See **[`docs/FEATURES.md`](docs/FEATURES.md)** for the detailed decision flow and behavior of every major layer.

## Repository layout

```text
src/compat/v63/      V6.3 compatibility logic
src/adaptive/        reputation, intelligence, feedback, fingerprints, Telegram, redirects
src/storage/         D1/R2 persistence helpers
migrations/          D1 schema
legacy/              archived V6.3 reference
docs/                install, architecture, validation and feature documentation
test/                regression tests
community-feed       sanitized shared intelligence data branch
```

## Development

```bash
npm install
npm test
npx wrangler dev
```

## Production health

```text
GET /_health
```

reports major policy/readiness state including redirects, Telegram, exact-IP control, rate limiting, owner learning, ASN intelligence, honeypots and Community Intelligence.

## Security

Do not open issues containing tokens, credentials, raw IP lists, private telemetry, redirect secrets or Telegram secrets.

See [`SECURITY.md`](SECURITY.md).

## Project philosophy

V7 treats **AI as evidence, not truth**; **operator feedback as explicit truth**; **deterministic infrastructure policy as the cheapest first line**; and **shared intelligence as aggregate ASN-level data, never visitor-level data**.
