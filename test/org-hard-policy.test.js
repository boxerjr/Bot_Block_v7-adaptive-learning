import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { classifyOrganization } from "../src/adaptive/org-intelligence.js";
import {
  orgHardBlockEnabled,
  organizationRequiresHardBlock,
} from "../src/adaptive/org-hard-policy.js";

const policy = readFileSync(
  new URL("../src/m22-policy-enforcing-entry.js", import.meta.url),
  "utf8"
);
const hardPolicy = readFileSync(
  new URL("../src/adaptive/org-hard-policy.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);

test("hosting and VPN/proxy organization classes are deterministic hard policy", () => {
  for (const org of [
    "IONOS SE",
    "DigitalOcean, LLC",
    "OVH SAS",
    "Hetzner Online GmbH",
    "VPN Consumer Montevideo, Uruguay",
    "Residential Proxy Network",
  ]) {
    const profile = classifyOrganization(org);
    assert.ok(["hosting_cloud", "vpn_proxy"].includes(profile.class), org);
    assert.ok(profile.confidence >= 90, org);
    assert.equal(
      organizationRequiresHardBlock({ ORG_HARD_BLOCK_ENABLED: "true" }, profile),
      true,
      org
    );
  }
});

test("consumer access organizations are not promoted to hard ASN", () => {
  for (const org of ["Telefonica de Espana", "Digi Spain Telecom", "Orange Spain"]) {
    const profile = classifyOrganization(org);
    assert.equal(profile.class, "consumer_isp", org);
    assert.equal(
      organizationRequiresHardBlock({ ORG_HARD_BLOCK_ENABLED: "true" }, profile),
      false,
      org
    );
  }
});

test("organization hard policy can be disabled explicitly", () => {
  const profile = classifyOrganization("DigitalOcean, LLC");
  assert.equal(orgHardBlockEnabled({ ORG_HARD_BLOCK_ENABLED: "false" }), false);
  assert.equal(
    organizationRequiresHardBlock({ ORG_HARD_BLOCK_ENABLED: "false" }, profile),
    false
  );
});

test("hosting/VPN org gate runs before country and persists ASN as hard", () => {
  assert.match(wrangler, /"ORG_HARD_BLOCK_ENABLED": "true"/);
  assert.match(policy, /getOrgPromotedHardAsn/);
  assert.match(policy, /organizationRequiresHardBlock/);
  assert.match(policy, /promoteOrgAsnToHard/);
  assert.match(policy, /source: "org_policy_auto"/);
  const orgIndex = policy.indexOf("if (organizationRequiresHardBlock(env, orgIntel))");
  const countryIndex = policy.indexOf("if (!countryAllowed(env, network.country))");
  assert.ok(orgIndex >= 0);
  assert.ok(countryIndex > orgIndex);
  assert.match(hardPolicy, /CREATE TABLE IF NOT EXISTS org_policy_hard_asns/);
  assert.match(hardPolicy, /tier: "hard"/);
});

test("org hard ASN memory stores no raw IP, UA, or raw organization name", () => {
  assert.doesNotMatch(hardPolicy, /cf-connecting-ip/i);
  assert.doesNotMatch(hardPolicy, /user-agent/i);
  assert.doesNotMatch(hardPolicy, /organization_name/i);
  assert.match(policy, /m22_org_hard_policy_is_training_truth: false/);
});
