import worker from "./v7-owner-timeout-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import {
  deriveManualIpKey,
  isManualIpBlocked,
  setManualIpBlocked,
  sendTelegramWithKeyboard,
} from "./adaptive/manual-ip-block.js";
import {
  buildTelegramIpKeyCallbackKeyboard,
  ensureTelegramWebhook,
} from "./adaptive/telegram-callback.js";
import { redirectResponse } from "./adaptive/redirect-policy.js";
import { classifyOrganization } from "./adaptive/org-intelligence.js";
import {
  orgHardPromotionEnabled,
  promoteAsnToHardFromOrganization,
} from "./adaptive/asn-intelligence.js";
import {
  classifyHoneypotPath,
  honeypotEnforcingEnabled,
  honeypotRuleStats,
} from "./adaptive/honeypot-intelligence.js";

function waitUntil(ctx, promise) {
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else return promise;
}

function clean(value, max = 180) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, max);
}

function blockFallbackResponse() {
  return new Response(null, {
    status: 404,
    headers: {
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
      "referrer-policy": "no-referrer",
    },
  });
}

function isInternalPath(pathname = "/") {
  return (
    pathname === "/_health" ||
    pathname.startsWith("/_telegram/") ||
    pathname.startsWith("/_shadow/")
  );
}

async function globalExactIpBlock(request, env) {
  if (!env?.DB || !env?.CHALLENGE_SECRET) return null;
  try {
    const ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request));
    if (!ipKey || !(await isManualIpBlocked(env.DB, ipKey))) return null;
    return redirectResponse(request, env, "block") || blockFallbackResponse();
  } catch {
    return null;
  }
}

async function buildBlockedKeyboard(request, env, ipKey) {
  if (
    !ipKey ||
    !env?.CHALLENGE_SECRET ||
    !env?.TELEGRAM_TOKEN ||
    !env?.TELEGRAM_CHAT_ID
  ) {
    return null;
  }

  try {
    // Keep direct HMAC exact-IP controls browser-independent, consistent with
    // the existing operational Telegram controls.
    await ensureTelegramWebhook(env, request.url);
    return await buildTelegramIpKeyCallbackKeyboard(
      env.CHALLENGE_SECRET,
      ipKey,
      "blocked"
    );
  } catch {
    return null;
  }
}

function honeypotMessage({ network, match, orgIntel, promotion }) {
  const lines = [
    "🪤 BLOCK_BY_HONEYPOT",
    `Path: ${clean(match.path, 260)}`,
    `Matched: ${clean(match.matchedPath || "?")}`,
    `HoneypotSource: ${clean(match.source || "unknown")}`,
    `HoneypotRule: ${clean(match.rule || "unknown")}`,
    `Country: ${clean(network.country || "?")}`,
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    `OrgIntel: ${clean(orgIntel.class || "unknown")} conf=${Number(orgIntel.confidence || 0)} rule=${clean(orgIntel.matchedRule || "none")}`,
  ];

  if (promotion?.promoted) {
    lines.push(`ASNPromotion: HARD source=${clean(promotion.source || "org_auto_hard")}`);
  } else {
    lines.push("ASNPromotion: none (consumer/mobile ASN is not poisoned by one path probe)");
  }

  lines.push(
    "Decision: block",
    "ExactIP: auto-blocked",
    "PolicyOrder: exact-IP → honeypot → ASN/Org → country → device → AI",
    "AI: skipped — hostile path is deterministic",
    "DatasetEligible: false",
    "RawIP/UA stored: false"
  );
  return lines.join("\n");
}

async function handleHoneypot(request, env, ctx, match) {
  const network = networkInfo(request);
  const orgIntel = classifyOrganization(network.org);

  let promotion = null;
  if (
    orgHardPromotionEnabled(env) &&
    ["hosting_cloud", "vpn_proxy"].includes(orgIntel.class)
  ) {
    try {
      promotion = await promoteAsnToHardFromOrganization(
        env,
        network.asn,
        orgIntel.class,
        orgIntel.matchedRule
      );
    } catch {}
  }

  let ipKey = null;
  let alreadyBlocked = false;
  if (env?.DB && env?.CHALLENGE_SECRET) {
    try {
      ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request));
      if (ipKey) {
        alreadyBlocked = await isManualIpBlocked(env.DB, ipKey);
        if (!alreadyBlocked) {
          // eventId is intentionally null: this is deterministic path evidence,
          // not a browser event and therefore must not invent a training label.
          await setManualIpBlocked(env.DB, ipKey, null);
        }
      }
    } catch {}
  }

  // Only announce the first honeypot hit for an exact IP. Once persisted as
  // blocked, later external requests are rejected by globalExactIpBlock.
  if (!alreadyBlocked) {
    const keyboard = await buildBlockedKeyboard(request, env, ipKey);
    waitUntil(
      ctx,
      sendTelegramWithKeyboard(
        env,
        honeypotMessage({ network, match, orgIntel, promotion }),
        keyboard
      )
    );
  }

  return redirectResponse(request, env, "block") || blockFallbackResponse();
}

async function health(request, env, ctx) {
  const response = await worker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const stats = honeypotRuleStats();
  return Response.json(
    {
      ...data,
      v7_global_exact_ip_block: true,
      v7_honeypot_enforcing: honeypotEnforcingEnabled(env),
      v7_honeypot_precedes_asn_country_ai: true,
      v7_honeypot_auto_blocks_exact_ip: true,
      v7_honeypot_ai_skipped: true,
      v7_honeypot_baseline_rules: stats.baseline,
      v7_honeypot_extended_exact_rules: stats.extendedExact,
      v7_honeypot_extended_prefix_rules: stats.extendedPrefix,
      v7_honeypot_total_rule_entries: stats.totalRuleEntries,
      v7_honeypot_raw_ip_stored: false,
      v7_honeypot_training_eligible: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return health(request, env, ctx);
    }

    // Never let operational callback/probe endpoints be swallowed by the
    // global exact-IP/honeypot gate.
    if (isInternalPath(url.pathname)) {
      return worker.fetch(request, env, ctx);
    }

    const blocked = await globalExactIpBlock(request, env);
    if (blocked) return blocked;

    if (honeypotEnforcingEnabled(env)) {
      const match = classifyHoneypotPath(url.pathname);
      if (match.matched) {
        return handleHoneypot(request, env, ctx, match);
      }
    }

    return worker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    if (typeof worker.scheduled === "function") {
      return worker.scheduled(controller, env, ctx);
    }
  },
};
