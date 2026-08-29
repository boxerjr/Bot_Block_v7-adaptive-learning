# ASN intelligence

V7 uses a tiered ASN policy before country filtering.

## Order

1. exact-IP manual preflight in production
2. hard ASN intelligence
3. country policy
4. mobile-only device policy
5. monitor / fingerprint / AI / adaptive reputation

This makes known hosting or high-confidence hostile infrastructure appear as `BLOCK_BY_ASN` instead of being hidden behind a country block.

## Sources

### V6.3 static seeds

The immutable V6.3 compatibility policy remains the local seed source:

- `HARD_ASNS`: deterministic hard-block seeds such as OVH, DigitalOcean, Vultr, Hetzner and selected cloud infrastructure already present in V6.3.
- `RISK_ASNS`: risk-only seeds. They are not automatically promoted to hard block by this feature.
- `SAFE_ASNS`: known access/carrier networks. Static hard blocking never overrides these, although an active Spamhaus ASN-DROP listing has higher priority.

### Spamhaus ASN-DROP

V7 can refresh the public Spamhaus ASN-DROP dataset once per day from:

`https://www.spamhaus.org/drop/asndrop.json`

Spamhaus describes ASN-DROP as ASNs controlled by spammers or cyber-criminals, including hijacked ASNs, intended for drop-all-traffic use. V7 stores only the ASN classification and feed metadata needed for enforcement; it does not add raw client IP or UA data.

Spamhaus Project attribution: data from the Spamhaus DROP / ASN-DROP project. Feed copyright, timestamp and terms metadata are retained in D1 when supplied by the source feed. See Spamhaus DROP usage terms for current conditions.

## Variables

- `ASN_HARD_BLOCK_ENABLED=true` enables hard ASN enforcement.
- `ASN_SPAMHAUS_DROP_ENABLED=true` enables the daily Spamhaus ASN-DROP refresh and lookup.

Both can be disabled independently without changing the V6.3 compatibility source lists.

## Safety boundary

Not every hosting, cloud, VPN, CDN or business ASN is automatically treated as 100% hostile. Hard blocking is restricted to the V6.3 hard seeds and high-confidence ASN-DROP data. Broader hosting/provider datasets should be introduced as risk priors unless there is enough evidence to promote a specific ASN to hard block.
