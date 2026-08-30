# V7 Adaptive Learning — feature guide

This document explains what each major V7 layer does and what it does **not** do.

## 1. Global exact-IP block

Telegram/manual blocks and selected automatic blocks use a keyed HMAC identifier. V7 does not persist the raw IP in the block row.

An already-blocked exact IP is rejected before the browser probe.

## 2. Local request-target security and global honeypot paths

V7 independently implements local checks for high-confidence exploit request
targets: encoded/double-encoded traversal, null-byte and CRLF injection,
`php://`/`file://` wrappers, PHP runtime overrides, response-splitting probes,
command-download probes and secret/config file queries. These deterministic
matches skip AI, block only the exact source IP and are never used as training
labels. The raw query is not persisted.

The security categories were reviewed against the public
[`Cloudflare-WAF-Expressions`](https://github.com/sefinek/Cloudflare-WAF-Expressions/blob/main/rules/expressions.md)
collection. V7 does not copy or execute its GPL-3.0 expressions or updater code
and has no runtime dependency on that project.

V7 contains the immutable V6.3 honeypot baseline plus an extended V7 layer for common scanner targets such as environment files, source-control metadata, credentials, admin panels, database dumps, backups and debug endpoints.

Examples:

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

A honeypot hit is deterministic hostile-path evidence:

```text
honeypot hit
→ AI skipped
→ exact IP blocked
→ BLOCK_URL (or blank 404 fallback)
```

A honeypot hit from a consumer/mobile ASN does **not** hard-block the entire ISP.

## 3. Community Intelligence

Every V7 installation can consume the public upstream community feed.

Shared `HARD` entries are restricted to deterministic hosting/VPN/proxy infrastructure derived by V7's own organization policy.

Strong feedback consensus is published only as `RISK`, not automatically converted to global hard block.

The shared feed excludes:

- raw IP
- User-Agent
- fingerprint IDs
- browser telemetry
- event IDs
- Telegram data
- third-party Spamhaus records

## 3A. Local static bot intelligence

V7 includes a curated, local set of precise scanner, automation, crawler and
declared-bot signatures. The useful signatures are vendored into the Worker;
production does not download or depend on another blocker.

Under `HUMANS_ONLY=true`, a precise declared crawler such as `GPTBot`,
`ClaudeBot`, `Googlebot`, `Bytespider` or `SemrushBot` is rejected before ASN,
country, browser and AI work. High-confidence scanner/automation clients such
as `sqlmap`, `masscan`, `Acunetix`, `Nmap`, `python-requests` and headless
frameworks are rejected regardless of the human-only toggle.

Ambiguous short names, upstream raw-IP lists and upstream referrer lists are
not included. A match does not create a truth label, alter ASN reputation, or
store the raw User-Agent. `LOCAL_STATIC_BOT_INTEL_ENABLED` is an optional kill
switch and defaults to `true`.

## 4. ASN Intelligence

V7 combines several ASN sources:

- immutable V6.3 `HARD_ASNS`
- immutable V6.3 `RISK_ASNS`
- immutable V6.3 `SAFE_ASNS`
- local dynamic `org_auto_hard` ASN promotion
- Spamhaus ASN-DROP operational lookup
- V7 Community Intelligence

Hard ASN policy runs before country/device/browser AI.

## 5. Organization Intelligence

Cloudflare's `asOrganization` string is normalized into classes such as:

```text
consumer_isp
mobile_carrier
hosting_cloud
vpn_proxy
unknown
```

Examples of hosting/cloud rules include IONOS, DigitalOcean, OVH, Hetzner, Vultr, Linode, Leaseweb, Contabo, AWS, Google Cloud, Azure and Oracle Cloud.

Examples of Spanish consumer-access rules include Telefonica/Movistar, Digi, Orange, Vodafone, Jazztel, MasMovil, Euskaltel and other access providers.

Under the strict production policy:

```text
hosting_cloud → deterministic block + ASN promotion to HARD
vpn_proxy     → deterministic block + ASN promotion to HARD
consumer_isp  → no automatic human status; continue inspection
mobile_carrier→ no automatic human status; continue inspection
```

A real person using a VPN/VPS/cloud connection is intentionally denied under this policy.

## 6. Country policy

`ALLOWED_COUNTRIES` is evaluated after hard infrastructure gates.

Example:

```text
ALLOWED_COUNTRIES=ES
```

means ordinary traffic outside Spain is not eligible to continue to the normal browser flow.

## 7. Mobile-only device policy

With:

```text
MOBILE_ONLY=true
```

an obvious desktop is blocked before deep browser AI.

A mobile claim is not automatically trusted; it only passes the header/device gate and still has to survive the remaining checks.

## 8. Browser probe and local signals

Allowed requests enter a silent browser inspection stage that collects runtime consistency signals. These feed local scoring and fingerprint reputation.

The system checks coherence across browser/device characteristics rather than trusting a single User-Agent string.

## 9. Fingerprint reputation

A keyed pseudonymous fingerprint is derived from stable browser material. It is not the raw IP and the raw UA is not stored as the fingerprint ID.

Fingerprint reputation reacts faster than ASN reputation because its evidence half-life is shorter.

## 10. Workers AI

Workers AI receives sanitized network/browser evidence and organization intelligence. It returns a classification/risk opinion.

AI output is **not** a truth label.

V7 does not train Llama after every request. AI is one signal inside the decision pipeline.

## 11. Adaptive D1 reputation

Explicit operator feedback updates D1 reputation for ASN and fingerprint entities.

Supported labels include:

```text
human_confirmed
bot_confirmed
spoof_confirmed
false_positive
false_negative
uncertain
```

`human_confirmed` and `false_positive` add human-side evidence. `bot_confirmed`, `spoof_confirmed` and `false_negative` add hostile-side evidence. Evidence decays over time.

## 12. Telegram operator controls

Standard traffic can expose:

```text
🚫 BLOCK IP
🔓 UNBLOCK IP
```

An operator `BLOCK IP` on an originally allowed event is a `false_negative` correction and rebuilds reputation.

`UNBLOCK IP` restores exact-IP access but does not erase prior truth feedback.

## 13. OWNER_LEARNING_MODE

Default:

```text
OWNER_LEARNING_MODE=false
```

During a controlled owner-only session, set it to `true`. A `HUMAN_PASS` then receives:

```text
✅ IT'S ME
❌ NOT ME
```

`IT'S ME` writes `human_confirmed` with confidence 100.

`NOT ME` writes `false_negative` with confidence 100 and blocks the exact IP.

If no `IT'S ME` confirmation arrives within three minutes, the pending controlled-session event becomes automatic `NOT ME` and the exact IP is blocked. If the timer write races with a callback, V7 falls back to the original event timestamp but keeps the same three-minute deadline. Because the Cloudflare sweep runs once per minute, enforcement may occur shortly after the exact three-minute deadline.

Never leave OWNER learning enabled for uncontrolled public traffic.

## 14. Rate limiting

The public monitor uses privacy-preserving exact-IP HMAC state.

Default:

```text
RATE_LIMIT_PER_MIN=3
```

The fourth request inside the rolling window triggers an exact-IP automatic block. `UNBLOCK IP` clears the old limiter state so access is actually restored.

## 15. Redirect engine

With `REDIRECT_ENFORCING=true`:

```text
confirmed human → ORIGIN_URL
block/review     → BLOCK_URL
```

Targets must be valid HTTPS URLs and a same-origin loop guard is applied.

If a block redirect target is unavailable, blocked traffic falls back to a blank 404 response.

## 16. D1 vs R2

D1 stores operational events, explicit feedback, reputation, exact-IP HMAC state and intelligence metadata.

R2 is reserved for controlled dataset-eligible material/model artifacts.

Ordinary public monitor traffic is intentionally:

```text
dataset_eligible=false
training_eligible=false
r2_written=false
```

## 17. Spamhaus ASN-DROP

V7 can refresh ASN-DROP operationally once per day and use active entries as hard infrastructure intelligence.

Those third-party records are **not republished** into the V7 Community Intelligence GitHub feed.

## 18. Health endpoint

`GET /_health` reports active configuration and readiness for major layers, including redirects, Telegram, owner learning, honeypots, ASN intelligence and community intelligence.

## 19. Production decision order

For an external request, the effective fast path is:

```text
exact-IP block
→ local request-target security + honeypot
→ local static bot/scanner signature
→ community HARD ASN
→ local/static/external HARD ASN + Org infrastructure
→ country
→ mobile/device
→ rate/browser/fingerprint/local signals
→ Workers AI
→ adaptive V7 reputation
→ final redirect
```

The objective is to spend expensive browser/AI work only on traffic that survives deterministic infrastructure and policy gates.
