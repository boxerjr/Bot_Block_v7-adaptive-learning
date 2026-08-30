import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  classifyAsn,
  organizationRuleEligibleForHardPromotion,
} from "../src/adaptive/asn-intelligence.js";

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

test("hard ASN and organization infrastructure gate execute before country", () => {
  assert.match(
    policy,
    /m22_policy_enforcement_order: \["hard_asn_or_org_infrastructure", "country", "mobile_only_device", "manual_ip", "monitor_ai"\]/
  );
  const asnIndex = policy.indexOf("const asnIntel = await classifyAsn");
  const orgIndex = policy.indexOf("const orgIntel = classifyOrganization");
  const countryIndex = policy.indexOf("if (!countryAllowed(env, network.country))");
  assert.ok(asnIndex >= 0);
  assert.ok(orgIndex > asnIndex);
  assert.ok(countryIndex > orgIndex);
  assert.match(policy, /BLOCK_BY_ASN/);
  assert.match(policy, /PolicyOrder: ASN\/Org infrastructure before country/);
});

test("hosting and VPN organization classes remain deterministic request blocks", () => {
  assert.match(wrangler, /"ORG_INFRASTRUCTURE_HARD_BLOCK_ENABLED"\s*:\s*"true"/);
  assert.match(policy, /\["hosting_cloud", "vpn_proxy"\]\.includes\(orgIntel\.class\)/);
  assert.match(policy, /promoteAsnToHardFromOrganization/);
});

test("only provider-specific organization rules can persist an ASN as org_auto_hard", () => {
  assert.equal(organizationRuleEligibleForHardPromotion("hosting_cloud", "ovh"), true);
  assert.equal(organizationRuleEligibleForHardPromotion("hosting_cloud", "amazon_web_services"), true);
  assert.equal(organizationRuleEligibleForHardPromotion("vpn_proxy", "tor_exit"), true);

  for (const genericRule of [
    "consumer_vpn",
    "vpn_keyword",
    "proxy_keyword",
    "residential_proxy",
    "anonymizer_keyword",
    "privacy_network",
  ]) {
    assert.equal(
      organizationRuleEligibleForHardPromotion("vpn_proxy", genericRule),
      false,
      genericRule
    );
  }

  assert.match(intel, /generic_organization_rule_not_persisted/);
  assert.match(intel, /source = 'org_auto_hard'/);
  assert.match(intel, /VALUES \(\?, 'org_auto_hard', 'hard'/);
});

test("Spamhaus ASN-DROP is enabled and refreshed from cron no more than daily", () => {
  assert.match(wrangler, /"ASN_HARD_BLOCK_ENABLED"\s*:\s*"true"/);
  assert.match(wrangler, /"ASN_SPAMHAUS_DROP_ENABLED"\s*:\s*"true"/);
  assert.match(scheduler, /refreshSpamhausAsnDrop/);
  assert.match(intel, /https:\/\/www\.spamhaus\.org\/drop\/asndrop\.json/);
  assert.match(intel, /24 \* 60 \* 60 \* 1000/);
  assert.match(intel, /spamhaus_asndrop_next_refresh_ms/);
});

test("external and organization ASN intelligence do not store raw IP or UA", () => {
  assert.doesNotMatch(intel, /cf-connecting-ip/i);
  assert.doesNotMatch(intel, /user-agent.*event/i);
  assert.match(policy, /RawIP\/UA stored: false/);
});
