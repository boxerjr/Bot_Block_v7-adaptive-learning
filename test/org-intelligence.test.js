import test from "node:test";
import assert from "node:assert/strict";

import { classifyOrganization } from "../src/adaptive/org-intelligence.js";

test("classifies well-known hosting providers", () => {
  for (const org of ["IONOS SE", "DigitalOcean, LLC", "OVH SAS", "Hetzner Online GmbH"]) {
    const result = classifyOrganization(org);
    assert.equal(result.class, "hosting_cloud", org);
    assert.ok(result.confidence >= 95, org);
    assert.ok(result.riskDelta >= 10, org);
    assert.equal(result.hardBlock, false, org);
  }
});

test("classifies VPN/proxy organization names with higher risk prior", () => {
  const result = classifyOrganization("VPN Consumer Montevideo, Uruguay");
  assert.equal(result.class, "vpn_proxy");
  assert.ok(result.confidence >= 95);
  assert.ok(result.riskDelta > 14);
  assert.equal(result.hardBlock, false);
});

test("classifies Spanish consumer access providers without granting human status", () => {
  for (const org of ["Telefonica de Espana", "Digi Spain Telecom", "Orange Spain"]) {
    const result = classifyOrganization(org);
    assert.equal(result.class, "consumer_isp", org);
    assert.ok(result.confidence >= 95, org);
    assert.equal(result.riskDelta, 0, org);
    assert.equal(result.hardBlock, false, org);
  }
});

test("unknown organizations remain neutral", () => {
  const result = classifyOrganization("Example Research Cooperative");
  assert.equal(result.class, "unknown");
  assert.equal(result.riskDelta, 0);
  assert.equal(result.hardBlock, false);
});
