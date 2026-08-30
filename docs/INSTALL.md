# Install V7 Adaptive Learning on a new Cloudflare account

This guide installs a clean V7 instance without copying the original project's D1 data, R2 data, redirect destinations, Telegram credentials, or other secrets.

## 1. Requirements

You need:

- a Cloudflare account with Workers, D1, R2 and Workers AI available
- Node.js 20+ and npm
- Git
- a GitHub account if you want Git-based deployment and the optional community publisher
- a Telegram bot only if you want Telegram alerts and operator buttons

Clone your fork or this repository:

```bash
git clone https://github.com/boxerjr/Bot_Block_v7-adaptive-learning.git
cd Bot_Block_v7-adaptive-learning
npm install
```

Authenticate Wrangler:

```bash
npx wrangler login
```

## 2. Create a new D1 database

```bash
npx wrangler d1 create v7-adaptive-learning
```

Cloudflare prints a `database_id`. Copy `wrangler.example.jsonc` to your own `wrangler.jsonc` and replace:

```text
REPLACE_WITH_YOUR_D1_DATABASE_ID
```

with the ID Cloudflare returned.

Do not reuse another installation's D1 database ID.

## 3. Create the R2 dataset bucket

```bash
npx wrangler r2 bucket create v7-adaptive-dataset
```

The default configuration uses the R2 binding name `DATASET` and bucket name `v7-adaptive-dataset`.

R2 is used for controlled dataset-eligible captures. Ordinary public monitor traffic is not written to the training dataset.

## 4. Configure policy variables

The important defaults are in `wrangler.example.jsonc`.

For Spain-only mobile traffic, the defaults are already:

```text
ALLOWED_COUNTRIES=ES
MOBILE_ONLY=true
HUMANS_ONLY=true
LOCAL_STATIC_BOT_INTEL_ENABLED=true
LOCAL_REQUEST_SECURITY_ENABLED=true
RATE_LIMIT_PER_MIN=3
REDIRECT_ENFORCING=true
HONEYPOT_ENFORCING=true
ASN_HARD_BLOCK_ENABLED=true
ORG_INFRASTRUCTURE_HARD_BLOCK_ENABLED=true
COMMUNITY_INTEL_ENABLED=true
COMMUNITY_INTEL_HARD_BLOCK_ENABLED=true
OWNER_LEARNING_MODE=false
```

Change `ALLOWED_COUNTRIES` if your deployment targets another country. Multiple countries are comma-separated.

Keep `OWNER_LEARNING_MODE=false` for normal/public traffic. Enable it only during a controlled session where the operator can truthfully confirm `IT'S ME` / `NOT ME`.

## 5. Configure secrets

Never place real secrets in Git or in `wrangler.jsonc`.

Create a strong random challenge secret:

```bash
npx wrangler secret put CHALLENGE_SECRET
```

Create an admin secret:

```bash
npx wrangler secret put ADMIN_SECRET
```

Configure the real destination for accepted traffic:

```bash
npx wrangler secret put ORIGIN_URL
```

Configure the destination for blocked traffic:

```bash
npx wrangler secret put BLOCK_URL
```

Both redirect destinations must be HTTPS. If a block destination is not configured, blocked traffic falls back to a blank 404 response.

### Optional Telegram controls

If you want Telegram alerts and the `BLOCK IP`, `UNBLOCK IP`, `IT'S ME`, and `NOT ME` buttons:

```bash
npx wrangler secret put TELEGRAM_TOKEN
npx wrangler secret put TELEGRAM_CHAT_ID
```

Do not paste these values into issues, commits, screenshots, or public logs.

## 6. Apply D1 migrations

```bash
npm run d1:migrate:remote
```

This creates the event, feedback, reputation, controlled-capture, ASN intelligence, and community intelligence tables.

## 7. Run tests before deployment

```bash
npm test
```

Do not deploy if the regression suite fails.

## 8. Deploy

```bash
npm run deploy
```

After deployment, open:

```text
https://YOUR-WORKER-DOMAIN/_health
```

Important checks include:

```text
v7_redirect_requested: true
v7_honeypot_enforcing: true
v7_local_static_bot_intel_enabled: true
v7_local_static_bot_intel_runtime_external_dependency: false
v7_local_request_security_enabled: true
v7_local_request_security_implementation: independent_local
v7_local_request_security_runtime_external_dependency: false
v7_community_intel_upstream_enabled: true
v7_community_intel_hard_block_enabled: true
m22_asn_hard_block_enforcing: true
```

If you configured both redirect secrets, also verify the origin and block redirect readiness fields are true.

## 9. Connect your custom domain

In Cloudflare, attach the Worker to the domain or route that should be protected. The protected hostname should point to this Worker first; V7 then decides whether to redirect the visitor to `ORIGIN_URL` or `BLOCK_URL`.

Avoid setting `ORIGIN_URL` or `BLOCK_URL` to the same origin as the Worker. V7 contains a redirect loop guard, but the clean configuration is to use distinct destinations.

## 10. Verify the basic paths

A normal browser visit to `/` should enter the normal V7 browser inspection flow.

Normal browser support paths such as these are not honeypots:

```text
/favicon.ico
/robots.txt
```

A controlled request to a honeypot such as `/.env` should be treated as hostile, skip AI, block the exact IP, and use `BLOCK_URL` when configured. Do this only from a test IP you can later unblock.

An encoded traversal request such as `/?file=%252e%252e%252fetc%252fpasswd`
should receive the same deterministic treatment. V7 evaluates it locally and
does not contact or require another WAF/blocker project.

A known hosting/VPN organization should be blocked by the infrastructure policy before country/browser AI.

A request declaring a precise scanner or crawler User-Agent such as `sqlmap`,
`GPTBot` or `ClaudeBot` should be rejected locally before AI. The signatures
are part of the deployed Worker and require no external blocker or feed.

## 11. Optional: publish sanitized Community Intelligence to GitHub

The Worker exposes a privacy-safe export at:

```text
/_community/intelligence.json
```

The export intentionally excludes raw IPs, User-Agents, fingerprints, browser telemetry and event IDs. It also does not redistribute third-party Spamhaus feed entries.

To let this repository publish your sanitized export automatically, add this GitHub Actions repository secret:

```text
V7_COMMUNITY_FEED_URL
```

Its value must be the full URL of your deployed Worker export, for example:

```text
https://YOUR-WORKER-DOMAIN/_community/intelligence.json
```

The `Publish community intelligence` workflow runs every six hours and writes only the validated JSON feed to the `community-feed` branch. It never writes the feed directly to protected `main`.

If your repository's Actions policy disables write access for `GITHUB_TOKEN`, enable repository Actions `Read and write permissions` before using the publisher.

## 12. GitHub deployment option

For a production repository, protect `main` and deploy only after tests pass. A recommended flow is:

```text
feature branch
→ pull request
→ regression checks
→ merge main
→ Cloudflare Workers Build
```

This is safer than editing the production Worker directly in the Cloudflare editor.

## 13. Safe first-day test plan

On a fresh Cloudflare account, validate in this order:

1. `/_health` and bindings.
2. Normal mobile visit from an allowed country.
3. Desktop visit when `MOBILE_ONLY=true`.
4. Visit from a known hosting/VPN network.
5. Controlled honeypot request such as `/.env` from a disposable test IP.
6. Telegram `BLOCK IP` and `UNBLOCK IP` if Telegram is configured.
7. Enable `OWNER_LEARNING_MODE=true` only for a controlled session, test `IT'S ME`, then return it to `false` before public traffic.
8. Confirm the community export contains no per-user identifiers.

Never use a production user's traffic as a synthetic test label.
