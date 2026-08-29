import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classifyAsn } from "../src/adaptive/asn-intelligence.js";

const policy = readFileSync(
  new URL("../src/m22-policy-enforcing-entry.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);
const scheduler = readFileSync(
  new URL("../src/v7-owner-timeout-entry.js", import.meta.url),
  "utf8"
);
const intel = readFileSync(
  new URL("../src/adaptive/asn-intelligence.js", import.meta.url),
  "utf8"
);

test("OVH and other V6.3 hard ASNs are enforcing seeds", async () => {
  const ovh = await classifyAsn(
    { ASN_HARD_BLOCK_ENABLED: "true", ASN_SPAMHAUS_DROP_ENABLED: "false" },
    "AS16276"
  );
  assert.equal(ovh.tier, "hard");
  assert.equal(ovh.hardBlock, true);
  assert.equal(ovh.source, "v63_hard_asn");
});

test("known safe access ASN is not hard-blocked by static seed", async () => {
  const telefonica = await classifyAsn(
    { ASN_HARD_BLOCK_ENABLED: "true", ASN_SPAMHAUS_DROP_ENABLED: "false" },
    "AS3352"
  );
  assert.equal(telefonica.tier, "safe");
  assert.equal(telefonica.hardBlock, false);
});

test("hard ASN and hard organization gates execute before country", () => {
  assert.match(policy, /"hard_asn"/);
  assert.match(policy, /"hosting_vpn_org_to_hard_asn"/);
  const asnIndex = policy.indexOf("const asnIntel = await classifyAsn");
  const orgIndex = policy.indexOf("if (organizationRequiresHardBlock(env, orgIntel))");
  const countryIndex = policy.indexOf("if (!countryAllowed(env, network.country))");
  assert.ok(asnIndex >= 0);
  assert.ok(orgIndex > asnIndex);
  assert.ok(countryIndex > orgIndex);
  assert.match(policy, /BLOCK_BY_ASN/);
  assert.match(policy, /before country/);
});

test("Spamhaus ASN-DROP is enabled and refreshed from cron no more than daily", () => {
  assert.match(wrangler, /"ASN_HARD_BLOCK_ENABLED": "true"/);
  assert.match(wrangler, /"ASN_SPAMHAUS_DROP_ENABLED": "true"/);
  assert.match(scheduler, /refreshSpamhausAsnDrop/);
  assert.match(intel, /https:\/\/www\.spamhaus\.org\/drop\/asndrop\.json/);
  assert.match(intel, /24 \* 60 \* 60 \* 1000/);
  assert.match(intel, /spamhaus_asndrop_next_refresh_ms/);
});

test("external ASN feed does not store raw IP or UA", () => {
  assert.doesNotMatch(intel, /cf-connecting-ip/i);
  assert.doesNotMatch(intel, /user-agent.*event/i);
  assert.match(policy, /RawIP\/UA stored: false/);
});
