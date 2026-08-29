import { HONEYPOTS, HARD_ASNS, SAFE_ASNS, STRONG_BOT_UA } from "./policy.js";

function isHoneypotPath(path = "/") {
  return HONEYPOTS.some(
    (honeypot) => path === honeypot || path.startsWith(`${honeypot}/`)
  );
}

/**
 * Pure shadow evaluator for the early V6.3 request rules.
 *
 * This intentionally preserves V6.3 rule order:
 * honeypot -> country -> hard ASN -> verified bot -> strong bot UA.
 *
 * It does NOT mutate state, block traffic, redirect, or store raw IP/UA.
 */
export function evaluateV63EarlyRules({
  path = "/",
  ua = "",
  network = {},
  allowedCountries = new Set(["ES"]),
  humansOnly = true,
}) {
  if (isHoneypotPath(path)) {
    return {
      outcome: "block",
      stage: "honeypot",
      reason: "honeypot",
      state_block_ttl_seconds: 86400,
    };
  }

  if (
    network.country &&
    !allowedCountries.has(String(network.country).toUpperCase())
  ) {
    return {
      outcome: "block",
      stage: "country",
      reason: "blocked_country",
      state_block_ttl_seconds: null,
    };
  }

  if (
    network.asn &&
    HARD_ASNS.has(network.asn) &&
    !SAFE_ASNS.has(network.asn)
  ) {
    return {
      outcome: "block",
      stage: "hard_asn",
      reason: "hard_block_asn",
      state_block_ttl_seconds: 3600,
    };
  }

  if (humansOnly && network.bot?.verifiedBot) {
    return {
      outcome: "block",
      stage: "verified_bot",
      reason: "verified_bot_block",
      state_block_ttl_seconds: null,
    };
  }

  const uaLower = String(ua).toLowerCase();
  const strongBot = STRONG_BOT_UA.find((marker) => uaLower.includes(marker));

  if (strongBot) {
    return {
      outcome: "block",
      stage: "strong_bot_ua",
      reason: "automation_ua",
      matched_marker: strongBot,
      state_block_ttl_seconds: 3600,
    };
  }

  return {
    outcome: "continue",
    stage: "post_early_rules",
    reason: "no_early_block",
    state_block_ttl_seconds: null,
  };
}
