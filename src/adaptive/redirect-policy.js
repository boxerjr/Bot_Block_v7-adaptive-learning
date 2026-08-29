import { boolEnv } from "../engine/config.js";

const PLACEHOLDER_RE = /(DESTINATIA-TA|SITE-REAL-PE-CARE-IL-CONTROLEZI|example\.com)/i;
const HUMAN_CLASSES = new Set(["human_mobile", "human_desktop"]);
const HOSTILE_CLASSES = new Set(["automation", "crawler", "spoofed_device"]);

function parseTarget(value) {
  const raw = String(value || "").trim();
  if (!raw || PLACEHOLDER_RE.test(raw)) return null;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:") return null;
    url.hash = "";
    return url;
  } catch {
    return null;
  }
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

export function redirectState(env = {}) {
  const origin = parseTarget(env.ORIGIN_URL);
  const block = parseTarget(env.BLOCK_URL);
  const requested = boolEnv(env.REDIRECT_ENFORCING, false);
  const originConfigured = !!origin;
  const blockConfigured = !!block;
  const originEnabled = requested && originConfigured;
  const blockEnabled = requested && blockConfigured;

  return {
    requested,
    originConfigured,
    blockConfigured,
    originEnabled,
    blockEnabled,
    fullyConfigured: originConfigured && blockConfigured,
    enabled: originEnabled || blockEnabled,
    originUrl: origin?.toString() || null,
    blockUrl: block?.toString() || null,
  };
}

export function redirectResponse(request, env, action = "block") {
  const state = redirectState(env);
  const isOrigin = action === "origin";
  const enabled = isOrigin ? state.originEnabled : state.blockEnabled;
  const target = isOrigin ? state.originUrl : state.blockUrl;

  // Fail-safe behavior is per destination:
  // - configured target + REDIRECT_ENFORCING=true => redirect
  // - missing/invalid target => caller keeps its normal fallback (404 for blocked traffic)
  if (!enabled || !target || sameOrigin(request.url, target)) return null;

  return new Response(null, {
    status: 302,
    headers: {
      location: target,
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

export function chooseFinalRedirect({ env = {}, requestUrl = "", monitorDetection = {}, v7Shadow = null } = {}) {
  const state = redirectState(env);
  const classification = String(monitorDetection?.classification || "unknown").toLowerCase();
  const monitorDecision = String(monitorDetection?.final_decision || "unknown").toLowerCase();
  const v7Ready = v7Shadow?.ready === true;
  const v7Decision = String(v7Shadow?.decision || "unknown").toLowerCase();

  let action = "block";
  let reason = "unknown_or_fail_safe_block";

  if (HOSTILE_CLASSES.has(classification)) {
    reason = `hostile_class:${classification}`;
  } else if (monitorDecision === "block" || monitorDecision === "review") {
    reason = `monitor_${monitorDecision}`;
  } else if (v7Ready && (v7Decision === "block" || v7Decision === "review")) {
    reason = `v7_${v7Decision}`;
  } else if (monitorDecision === "allow" && HUMAN_CLASSES.has(classification)) {
    action = "origin";
    reason = `verified_${classification}`;
  }

  const isOrigin = action === "origin";
  const enabled = isOrigin ? state.originEnabled : state.blockEnabled;
  const url = isOrigin ? state.originUrl : state.blockUrl;

  if (!enabled || !url) {
    return {
      enabled: false,
      action,
      url: null,
      reason: isOrigin ? "origin_redirect_not_configured" : "block_redirect_not_configured",
    };
  }

  if (requestUrl && sameOrigin(requestUrl, url)) {
    return { enabled: false, action, url: null, reason: "redirect_loop_guard" };
  }

  return { enabled: true, action, url, reason };
}
