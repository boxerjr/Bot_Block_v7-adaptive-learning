import operationalWorker from "./m22-operational-monitor-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { boolEnv, csvSet } from "./engine/config.js";
import { evaluateV63MobileGate } from "./compat/v63/device.js";
import { checkMonitorRateLimit } from "./adaptive/monitor-rate-limit.js";
import { sendTelegramWithKeyboard } from "./adaptive/manual-ip-block.js";
import {
  classifyAsn,
  getAsnIntelligenceHealth,
} from "./adaptive/asn-intelligence.js";
import { classifyOrganization } from "./adaptive/org-intelligence.js";
import {
  getOrgHardPolicyHealth,
  getOrgPromotedHardAsn,
  organizationRequiresHardBlock,
  promoteOrgAsnToHard,
} from "./adaptive/org-hard-policy.js";

function waitUntil(ctx, promise) {
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else return promise;
}

function isMonitorPage(pathname) {
  return pathname === "/" || pathname === "" || pathname === "/check" || pathname === "/check/";
}

function countryAllowed(env, country) {
  const allowed = csvSet(env.ALLOWED_COUNTRIES, "ES");
  const normalized = String(country || "").trim().toUpperCase();
  if (!normalized) return true;
  return allowed.size === 0 || allowed.has(normalized);
}

function rateLimitPerMinute(env) {
  return Math.max(1, Math.min(120, Number(env.RATE_LIMIT_PER_MIN || 3) || 3));
}

function clean(value, max = 160) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, max);
}

function blockResponse() {
  return new Response("Not Found", {
    status: 404,
    headers: {
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function buildAsnBlockMessage(network = {}, intel = {}) {
  const lines = [
    "🚫 BLOCK_BY_ASN",
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    `Country: ${clean(network.country || "?")}`,
    `ASNClass: ${clean(intel.tier || "hard")}`,
    `ASNSource: ${clean(intel.source || "unknown")}`,
    `Reason: ${clean(intel.reason || "hard_block_asn")}`,
  ];

  if (intel.orgClass) {
    lines.push(
      `OrgClass: ${clean(intel.orgClass)}`,
      `OrgRule: ${clean(intel.matchedRule || "none")}`,
      `ASNPromotedHard: ${intel.persisted === false ? "pending_or_unavailable" : "true"}`
    );
  }

  lines.push(
    "PolicyOrder: HARD ASN / HOSTING-VPN ORG before country",
    "Decision: block",
    "Enforcement: BLOCK_URL or 404 fallback",
    "DatasetEligible: false",
    "RawIP/UA stored: false"
  );
  return lines.join("\n");
}

function buildDeviceBlockMessage(network = {}, gate = {}) {
  return [
    "🖥️ BLOCK_BY_DEVICE",
    `Country: ${clean(network.country || "?")}`,
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    "MobileOnly: true",
    `Device: ${clean(gate.device || "desktop")}`,
    `Reason: ${clean(gate.reason || "desktop_not_allowed")}`,
    "Decision: block",
    "Enforcement: BLOCK_URL or 404 fallback",
    "DatasetEligible: false",
    "RawIP/UA stored: false",
  ].join("\n");
}

async function enforceAsnBlock(request, env, ctx, network, intel) {
  const limiter = await checkMonitorRateLimit({
    db: env.DB,
    secret: env.CHALLENGE_SECRET,
    ip: clientIp(request),
    limit: rateLimitPerMinute(env),
  });

  if (limiter.allowed) {
    waitUntil(ctx, sendTelegramWithKeyboard(env, buildAsnBlockMessage(network, intel), null));
  }

  return blockResponse();
}

async function health(request, env, ctx) {
  const response = await operationalWorker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const [asnHealth, orgHardHealth] = await Promise.all([
    getAsnIntelligenceHealth(env),
    getOrgHardPolicyHealth(env),
  ]);

  return Response.json(
    {
      ...data,
      m22_policy_enforcement_order: [
        "hard_asn",
        "hosting_vpn_org_to_hard_asn",
        "country",
        "mobile_only_device",
        "manual_ip",
        "monitor_ai",
      ],
      m22_asn_policy_precedes_country: true,
      m22_asn_hard_block_enforcing: asnHealth.hardBlockEnabled,
      m22_asn_static_hard_count: asnHealth.staticHardCount,
      m22_asn_static_risk_count: asnHealth.staticRiskCount,
      m22_asn_static_safe_count: asnHealth.staticSafeCount,
      m22_asn_spamhaus_drop_enabled: asnHealth.spamhausEnabled,
      m22_asn_spamhaus_drop_active_count: asnHealth.spamhausCount,
      m22_asn_spamhaus_last_success_ms: asnHealth.spamhausLastSuccessMs,
      m22_org_hard_block_enabled: orgHardHealth.enabled,
      m22_org_promoted_hard_asn_count: orgHardHealth.promotedAsnCount,
      m22_org_hard_classes: ["hosting_cloud", "vpn_proxy"],
      m22_org_hard_policy_is_training_truth: false,
      m22_asn_block_title: "BLOCK_BY_ASN",
      m22_mobile_only_policy_enabled: boolEnv(env.MOBILE_ONLY, true),
      m22_mobile_only_policy_precedes_monitor_verdict: true,
      m22_mobile_only_desktop_enforcing: boolEnv(env.MOBILE_ONLY, true),
      m22_mobile_only_desktop_block_status: 404,
      m22_desktop_block_title: "BLOCK_BY_DEVICE",
      m22_ai_bot_enforcing: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function monitorPage(request, env, ctx) {
  const network = networkInfo(request);

  // 1) An ASN previously learned from a high-confidence hosting/VPN Org is a
  // permanent hard policy ASN and is enforced before all other policy gates.
  const learnedOrgAsn = await getOrgPromotedHardAsn(env, network.asn);
  if (learnedOrgAsn?.hardBlock) {
    return enforceAsnBlock(request, env, ctx, network, {
      ...learnedOrgAsn,
      persisted: true,
    });
  }

  // 2) Static V6.3 hard ASNs and high-confidence external ASN intelligence.
  const asnIntel = await classifyAsn(env, network.asn);
  if (asnIntel.hardBlock) {
    return enforceAsnBlock(request, env, ctx, network, asnIntel);
  }

  // 3) Organization intelligence. Hosting/cloud and VPN/proxy organizations
  // are a deterministic deny policy for this deployment. The current request
  // is blocked immediately and its ASN is persisted as a hard ASN for future
  // requests. This is policy intelligence, not an ML ground-truth bot label.
  const orgIntel = classifyOrganization(network.org);
  if (organizationRequiresHardBlock(env, orgIntel)) {
    const promotion = await promoteOrgAsnToHard(env, network.asn, orgIntel);
    return enforceAsnBlock(request, env, ctx, network, {
      tier: "hard",
      source: "org_policy_auto",
      reason: promotion.promoted
        ? promotion.reason
        : orgIntel.class === "vpn_proxy"
          ? "organization_vpn_proxy_hard_policy"
          : "organization_hosting_cloud_hard_policy",
      hardBlock: true,
      orgClass: orgIntel.class,
      matchedRule: orgIntel.matchedRule,
      persisted: promotion.promoted,
    });
  }

  if (!countryAllowed(env, network.country)) {
    return operationalWorker.fetch(request, env, ctx);
  }

  if (boolEnv(env.MOBILE_ONLY, true)) {
    const gate = evaluateV63MobileGate({
      ua: request.headers.get("user-agent") || "",
      chMobile: request.headers.get("sec-ch-ua-mobile"),
      mobileOnly: true,
    });

    if (gate.outcome === "block") {
      const limiter = await checkMonitorRateLimit({
        db: env.DB,
        secret: env.CHALLENGE_SECRET,
        ip: clientIp(request),
        limit: rateLimitPerMinute(env),
      });

      if (limiter.allowed) {
        waitUntil(ctx, sendTelegramWithKeyboard(env, buildDeviceBlockMessage(network, gate), null));
      }

      return blockResponse();
    }
  }

  return operationalWorker.fetch(request, env, ctx);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return health(request, env, ctx);
    }

    if (isMonitorPage(url.pathname)) {
      return monitorPage(request, env, ctx);
    }

    return operationalWorker.fetch(request, env, ctx);
  },
};
