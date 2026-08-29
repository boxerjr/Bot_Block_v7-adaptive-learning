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
  return {
    requested,
    originConfigured: !!origin,
    blockConfigured: !!block,
    enabled: requested && !!origin && !!block,
    originUrl: origin?.toString() || null,
    blockUrl: block?.toString() || null,
  };
}

export function redirectResponse(request, env, action = "block") {
  const state = redirectState(env);
  if (!state.enabled) return null;
  const target = action === "origin" ? state.originUrl : state.blockUrl;
  if (!target || sameOrigin(request.url, target)) return null;
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
  if (!state.enabled) {
    return { enabled: false, action: "none", url: null, reason: "redirect_not_ready" };
  }

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

  const url = action === "origin" ? state.originUrl : state.blockUrl;
  if (!url || (requestUrl && sameOrigin(requestUrl, url))) {
    return { enabled: false, action: "none", url: null, reason: "redirect_loop_guard" };
  }

  return { enabled: true, action, url, reason };
}
