import test from "node:test";
import assert from "node:assert/strict";

import {
  HARD_ASNS,
  RISK_ASNS,
  SAFE_ASNS,
  HONEYPOTS,
  STRONG_BOT_UA,
} from "../src/compat/v63/policy.js";
import { evaluateV63EarlyRules } from "../src/compat/v63/preflight.js";

const ES = new Set(["ES"]);

function evaluate(overrides = {}) {
  return evaluateV63EarlyRules({
    path: "/",
    ua: "Mozilla/5.0",
    network: {
      country: "ES",
      asn: "AS14593",
      bot: { verifiedBot: false },
    },
    allowedCountries: ES,
    humansOnly: true,
    ...overrides,
  });
}

test("V6.3 policy list cardinalities stay locked", () => {
  assert.equal(HARD_ASNS.size, 19);
  assert.equal(RISK_ASNS.size, 70);
  assert.equal(SAFE_ASNS.size, 14);
  assert.equal(HONEYPOTS.length, 40);
  assert.equal(STRONG_BOT_UA.length, 25);
});

test("safe ES access continues past early rules", () => {
  const result = evaluate();
  assert.equal(result.outcome, "continue");
  assert.equal(result.reason, "no_early_block");
});

test("country rule blocks before ASN/UA rules", () => {
  const result = evaluate({
    ua: "curl/8.0",
    network: {
      country: "RO",
      asn: "AS16509",
      bot: { verifiedBot: true },
    },
  });
  assert.equal(result.outcome, "block");
  assert.equal(result.stage, "country");
  assert.equal(result.reason, "blocked_country");
});

test("honeypot rule has highest precedence in this early-rule stage", () => {
  const result = evaluate({
    path: "/.git/config",
    network: {
      country: "RO",
      asn: "AS16509",
      bot: { verifiedBot: true },
    },
  });
  assert.equal(result.stage, "honeypot");
  assert.equal(result.state_block_ttl_seconds, 86400);
});

test("hard ASN blocks in an allowed country", () => {
  const result = evaluate({
    network: {
      country: "ES",
      asn: "AS16509",
      bot: { verifiedBot: false },
    },
  });
  assert.equal(result.stage, "hard_asn");
  assert.equal(result.state_block_ttl_seconds, 3600);
});

test("verified bot blocks after country and hard-ASN checks", () => {
  const result = evaluate({
    network: {
      country: "ES",
      asn: "AS14593",
      bot: { verifiedBot: true },
    },
  });
  assert.equal(result.stage, "verified_bot");
});

test("strong automation UA blocks and reports the matched V6.3 marker", () => {
  const result = evaluate({ ua: "curl/8.7.1" });
  assert.equal(result.stage, "strong_bot_ua");
  assert.equal(result.matched_marker, "curl/");
  assert.equal(result.state_block_ttl_seconds, 3600);
});

test("risk ASN alone does not hard-block in the early-rule stage", () => {
  const result = evaluate({
    network: {
      country: "ES",
      asn: "AS13335",
      bot: { verifiedBot: false },
    },
  });
  assert.equal(result.outcome, "continue");
});
