# V7 Community Intelligence

The Community Intelligence feed lets separate V7 installations share high-confidence network intelligence without sharing individual visitor data.

## Design goals

The feed must be useful across deployments while remaining resistant to privacy leaks and poisoning.

It therefore shares only ASN-level records.

It never shares:

```text
raw IP
raw User-Agent
fingerprint ID
browser telemetry
event ID
Telegram content
cookies/tokens
redirect destinations
secrets
```

## Two tiers

### HARD

A shared HARD ASN must come from V7's deterministic organization infrastructure policy:

```text
hosting_cloud
vpn_proxy
```

Examples include a network identified as hosting/cloud/VPS infrastructure or VPN/proxy infrastructure.

These records are exported with:

```json
{
  "asn": "AS12345",
  "tier": "hard",
  "source": "v7_org_infrastructure",
  "reason": "org_hosting_cloud:provider_rule",
  "confidence": 100
}
```

A single operator click cannot create a shared HARD ASN.

### RISK

Strong hostile feedback can create a shared RISK ASN only when the local live reputation satisfies all of these minimum conditions:

```text
feedback_count >= 8
hostile_weight >= 6
human_weight <= 0.25
reputation_score <= 20
```

A feedback-derived RISK record is not automatically upgraded to global HARD.

This prevents a cluster of manual mistakes against a consumer ISP from immediately blocking that ISP for every V7 installation.

## Third-party feed isolation

Spamhaus ASN-DROP is used operationally by V7, but its records are deliberately excluded from the V7 GitHub community export.

The community repository publishes only intelligence derived by V7 itself.

## Worker export

When enabled, a V7 Worker provides:

```text
GET /_community/intelligence.json
```

The endpoint contains only the sanitized community schema. It does not expose D1 events or raw visitor records.

Default:

```text
COMMUNITY_INTEL_EXPORT_ENABLED=true
```

Set it to `false` if an installation should consume community intelligence but not expose its own sanitized export.

## GitHub publisher

The repository contains:

```text
.github/workflows/community-intelligence-publish.yml
```

The workflow reads the Worker export every six hours, validates the schema/privacy invariants, and updates:

```text
community-feed branch
└── community/intelligence.json
```

The feed branch is intentionally separate from protected `main`. A data refresh cannot modify production source code.

To activate publishing, configure the GitHub Actions repository secret:

```text
V7_COMMUNITY_FEED_URL
```

with the full export URL of the Worker.

## Consumption

By default, V7 reads the canonical upstream:

```text
https://raw.githubusercontent.com/boxerjr/Bot_Block_v7-adaptive-learning/community-feed/community/intelligence.json
```

The Worker refreshes it every six hours and stores a local D1 copy with a 24-hour expiry.

Configuration:

```text
COMMUNITY_INTEL_ENABLED=true
COMMUNITY_INTEL_HARD_BLOCK_ENABLED=true
```

A different trusted upstream can be selected with:

```text
COMMUNITY_INTEL_UPSTREAM_URL
```

If the upstream is unavailable or invalid, the last valid rows naturally expire instead of being kept forever.

## Poisoning resistance

V7 uses several barriers:

1. only ASN-level data is shared;
2. HARD accepts only deterministic V7 hosting/VPN/proxy source records;
3. feedback-derived entries remain RISK;
4. minimum feedback/evidence thresholds are validated both by the Worker exporter and the GitHub publishing workflow;
5. the feed parser rejects unknown source types and malformed ASNs;
6. feed data expires locally;
7. third-party records are not copied into the repository;
8. `main` source code is not modified by feed publishing.

## Important trust model

A community feed is intelligence, not mathematical proof that every connection from an ASN is malicious.

This project's strict default policy intentionally denies hosting/VPN/proxy infrastructure. Deployments with a different policy can set:

```text
COMMUNITY_INTEL_HARD_BLOCK_ENABLED=false
```

and still keep the rest of V7 running.
