import worker from "./v7-owner-timeout-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { boolEnv } from "./engine/config.js";
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
import { checkMonitorRateLimit } from "./adaptive/monitor-rate-limit.js";
import {
  buildCommunityIntelligenceExport,
  classifyCommunityAsn,
  communityExportEnabled,
  getCommunityIntelligenceHealth,
  refreshCommunityIntelligence,
} from "./adaptive/community-intelligence.js";
import {
  classifyLocalStaticUa,
  localStaticBotIntelEnabled,
  localStaticBotIntelStats,
} from "./adaptive/local-static-bot-intelligence.js";

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

function rateLimitPerMinute(env) {
  return Math.max(1, Math.min(120, Number(env.RATE_LIMIT_PER_MIN || 3) || 3));
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
    "PolicyOrder: exact-IP → honeypot → local static UA → community ASN → ASN/Org → country → device → AI",
    "AI: skipped — hostile path is deterministic",
    "DatasetEligible: false",
    "RawIP/UA stored: false"
  );
  return lines.join("\n");
}

function communityAsnMessage(network, intel) {
  return [
    "🌐 BLOCK_BY_COMMUNITY_ASN",
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    `Country: ${clean(network.country || "?")}`,
    `Tier: ${clean(intel.tier || "hard")}`,
    `Source: ${clean(intel.source || "community_repo")}`,
    `Reason: ${clean(intel.reason || "community_hosting_or_vpn")}`,
    `Confidence: ${Number(intel.confidence || 0)}`,
    "Policy: shared HARD contains deterministic hosting/VPN/proxy infrastructure only",
    "Decision: block",
    "AI: skipped",
    "RawIP/UA stored: false",
  ].join("\n");
}

function localStaticBotMessage(network, intel) {
  return [
    "🤖 BLOCK_BY_LOCAL_STATIC_UA",
    `Country: ${clean(network.country || "?")}`,
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    `Category: ${clean(intel.category || "declared_bot")}`,
    `Marker: ${clean(intel.marker || "unknown")}`,
    `Source: ${clean(intel.source || "v7_local_curated")}`,
    "Decision: block",
    "AI: skipped — local high-confidence signature",
    "External runtime dependency: false",
    "Training/reputation update: false",
    "RawIP/UA stored: false",
  ].join("\n");
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
          await setManualIpBlocked(env.DB, ipKey, null);
        }
      }
    } catch {}
  }

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

async function handleCommunityHardAsn(request, env, ctx, network, intel) {
  try {
    const limiter = await checkMonitorRateLimit({
      db: env.DB,
      secret: env.CHALLENGE_SECRET,
      ip: clientIp(request),
      limit: rateLimitPerMinute(env),
    });
    if (limiter.allowed) {
      waitUntil(ctx, sendTelegramWithKeyboard(env, communityAsnMessage(network, intel), null));
    }
  } catch {}
  return redirectResponse(request, env, "block") || blockFallbackResponse();
}

async function handleLocalStaticBot(request, env, ctx, network, intel) {
  try {
    const limiter = await checkMonitorRateLimit({
      db: env.DB,
      secret: env.CHALLENGE_SECRET,
      ip: clientIp(request),
      limit: rateLimitPerMinute(env),
    });
    if (limiter.allowed) {
      waitUntil(
        ctx,
        sendTelegramWithKeyboard(env, localStaticBotMessage(network, intel), null)
      );
    }
  } catch {}
  return redirectResponse(request, env, "block") || blockFallbackResponse();
}

async function communityExport(env) {
  if (!communityExportEnabled(env)) return blockFallbackResponse();
  const feed = await buildCommunityIntelligenceExport(env);
  if (!feed?.ready) {
    return Response.json(
      { schema_version: 1, ready: false, reason: feed?.reason || "unavailable" },
      { status: 503, headers: { "cache-control": "no-store" } }
    );
  }
  return Response.json(feed, {
    headers: {
      "cache-control": "public, max-age=300",
      "access-control-allow-origin": "*",
      "x-content-type-options": "nosniff",
    },
  });
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
  const localBotIntel = localStaticBotIntelStats();
  const community = await getCommunityIntelligenceHealth(env);
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
      v7_local_static_bot_intel_enabled: localStaticBotIntelEnabled(env),
      v7_local_static_bot_intel_mode: localBotIntel.mode,
      v7_local_static_bot_intel_runtime_external_dependency:
        localBotIntel.runtimeExternalDependency,
      v7_local_static_bot_intel_upstream_version:
        localBotIntel.upstreamVersion,
      v7_local_static_bot_intel_upstream_blob:
        localBotIntel.upstreamListBlob,
      v7_local_static_bot_intel_scanner_markers:
        localBotIntel.scannerAutomationMarkers,
      v7_local_static_bot_intel_declared_bot_markers:
        localBotIntel.declaredBotMarkers,
      v7_local_static_bot_intel_total_markers: localBotIntel.totalMarkers,
      v7_local_static_bot_intel_precedes_asn_country_ai: true,
      v7_local_static_bot_intel_raw_ua_stored: false,
      v7_local_static_bot_intel_training_eligible: false,
      v7_community_intel_export_enabled: community.exportEnabled,
      v7_community_intel_upstream_enabled: community.upstreamEnabled,
      v7_community_intel_hard_block_enabled: community.hardBlockEnabled,
      v7_community_intel_hard_count: community.hardCount,
      v7_community_intel_risk_count: community.riskCount,
      v7_community_intel_last_success_ms: community.lastSuccessMs,
      v7_community_intel_raw_ip_stored: false,
      v7_community_intel_external_feed_redistribution: false,
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

    if (url.pathname === "/_community/intelligence.json" && request.method === "GET") {
      return communityExport(env);
    }

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

    const network = networkInfo(request);
    if (localStaticBotIntelEnabled(env)) {
      const localBotIntel = classifyLocalStaticUa(
        request.headers.get("user-agent") || "",
        { humansOnly: boolEnv(env.HUMANS_ONLY, true) }
      );
      if (localBotIntel.matched && localBotIntel.tier === "hard") {
        return handleLocalStaticBot(request, env, ctx, network, localBotIntel);
      }
    }

    const communityIntel = await classifyCommunityAsn(env, network.asn);
    if (communityIntel?.hardBlock) {
      return handleCommunityHardAsn(request, env, ctx, network, communityIntel);
    }

    return worker.fetch(request, env, ctx);
  },

  async scheduled(controller, env, ctx) {
    const tasks = [refreshCommunityIntelligence(env, Date.now())];
    if (typeof worker.scheduled === "function") {
      tasks.push(worker.scheduled(controller, env, ctx));
    }
    const all = Promise.allSettled(tasks);
    if (ctx?.waitUntil) ctx.waitUntil(all);
    else await all;
  },
};
