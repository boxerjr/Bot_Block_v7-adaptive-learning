import policyWorker from "./m22-policy-enforcing-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import {
  chooseFinalRedirect,
  redirectResponse,
  redirectState,
} from "./adaptive/redirect-policy.js";
import {
  deriveManualIpKey,
  isManualIpBlocked,
  sendTelegramWithKeyboard,
} from "./adaptive/manual-ip-block.js";
import {
  buildTelegramEventIpKeyCallbackKeyboard,
  buildTelegramIpKeyCallbackKeyboard,
  ensureTelegramWebhook,
} from "./adaptive/telegram-callback.js";
import { buildTelegramDecisionMessage } from "./adaptive/telegram.js";

function waitUntil(ctx, promise) {
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else return promise;
}

function isMonitorPage(pathname) {
  return pathname === "/" || pathname === "" || pathname === "/check" || pathname === "/check/";
}

function silentRedirectShell(html) {
  const silentHead = `<style id="v7-silent-redirect-style">html[data-v7-silent="1"],html[data-v7-silent="1"] body{margin:0!important;width:100%!important;height:100%!important;min-height:100%!important;visibility:hidden!important;opacity:0!important;background:transparent!important;overflow:hidden!important}html[data-v7-silent="1"] body>*:not(script){display:none!important}</style>`;
  return html
    .replace(
      '<html lang="en">',
      '<html lang="en" data-v7-silent="1" style="visibility:hidden!important;opacity:0!important;background:transparent!important">'
    )
    .replace(
      "<body>",
      '<body style="visibility:hidden!important;opacity:0!important;background:transparent!important;margin:0!important">'
    )
    .replace("<title>V7 Public Traffic Monitor</title>", "<title></title>")
    .replace("</head>", `${silentHead}</head>`);
}

function blockFallbackResponse() {
  return new Response(null, {
    status: 404,
    headers: {
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

async function directExactIpBlock(request, env) {
  if (!env?.DB || !env?.CHALLENGE_SECRET) return null;
  try {
    const ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request));
    if (!ipKey || !(await isManualIpBlocked(env.DB, ipKey))) return null;

    return redirectResponse(request, env, "block") || blockFallbackResponse();
  } catch {
    return null;
  }
}

function rebuildDecision(data = {}) {
  return {
    finalDecision: data.final_decision || "unknown",
    decisionStage: data.decision_stage || "unknown",
    early: data.early_rules || null,
    deviceGate: data.device_gate || null,
    fingerprint: data.fingerprint || null,
    local: data.local || {},
    ai: {
      runAi: !!data.ai?.run,
      criticRun: !!data.ai?.critic_run,
      skippedReason: data.ai?.skipped_reason || null,
      ai: data.ai?.ai1 || null,
      critic: data.ai?.ai2 || null,
      humanEvidence: Number(data.ai?.human_evidence || 0),
      hardLocalBlock: !!data.ai?.hard_local_block,
      error: data.ai?.error || null,
    },
  };
}

function rebuildV7(data = {}) {
  const v7 = data.v7_shadow;
  if (!v7?.ready) return null;
  return {
    v7Decision: v7.decision || "unknown",
    v7Risk: Number(v7.risk || 0),
    comparison: v7.comparison || "unknown",
    baseRisk: Number(v7.base_risk || 0),
    asnAdjustment: Number(v7.asn_adjustment || 0),
    fingerprintAdjustment: Number(v7.fingerprint_adjustment || 0),
  };
}

function rebuildPolicy(data = {}) {
  const policy = data.policy_baseline || {};
  return {
    finalDecision: policy.final_decision || "unknown",
    wouldBlock: !!policy.would_block,
    decisionStage: policy.decision_stage || "unknown",
    reason: policy.reason || null,
  };
}

async function buildFinalTelegramControl(request, env, state = "unblocked", eventId = null) {
  if (!env?.DB || !env?.CHALLENGE_SECRET || !env?.TELEGRAM_TOKEN || !env?.TELEGRAM_CHAT_ID) {
    return { keyboard: null, ipKey: null, webhookConfigured: false, eventBound: false };
  }

  try {
    const ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request));
    if (!ipKey) {
      return { keyboard: null, ipKey: null, webhookConfigured: false, eventBound: false };
    }

    let keyboard = null;
    let eventBound = false;

    // Preferred production control: callback_data carries both a signed compact
    // event reference and the signed exact-IP HMAC. No event->IP D1 mapping is
    // required, so operator feedback remains learnable even if that mapping path
    // is unavailable.
    if (eventId) {
      keyboard = await buildTelegramEventIpKeyCallbackKeyboard(
        env.CHALLENGE_SECRET,
        eventId,
        ipKey,
        state
      );
      eventBound = !!keyboard;
    }

    // Reliability fallback: exact-IP block/unblock still works even when an
    // event cannot be represented. In that case no learning label is guessed.
    if (!keyboard) {
      keyboard = await buildTelegramIpKeyCallbackKeyboard(
        env.CHALLENGE_SECRET,
        ipKey,
        state
      );
    }

    let webhookConfigured = false;
    try {
      const webhook = await ensureTelegramWebhook(env, request.url);
      webhookConfigured = webhook.configured === true;
    } catch {}

    return { keyboard, ipKey, webhookConfigured, eventBound };
  } catch {
    return { keyboard: null, ipKey: null, webhookConfigured: false, eventBound: false };
  }
}

async function sendFinalTelegram(request, env, ctx, data) {
  if (!env?.TELEGRAM_TOKEN || !env?.TELEGRAM_CHAT_ID) {
    return { keyboardReady: false, webhookConfigured: false, eventBound: false };
  }

  const v63Decision = rebuildDecision(data);
  const monitorVerdict = data.monitor_verdict || {
    decision: data.monitor_detection?.final_decision || "unknown",
    classification: data.monitor_detection?.classification || "unknown",
    confidence: Number(data.monitor_detection?.confidence || 0),
    risk: Number(data.monitor_detection?.risk || 0),
    reasons: Array.isArray(data.monitor_detection?.reasons) ? data.monitor_detection.reasons : [],
  };
  const policyBaseline = rebuildPolicy(data);
  const v7 = rebuildV7(data);
  const network = networkInfo(request);

  const telegramDecision = {
    ...v63Decision,
    finalDecision: monitorVerdict.decision || "unknown",
    decisionStage: "monitor_policy_neutral",
    monitorVerdict,
  };

  const telegramCore = buildTelegramDecisionMessage({
    sessionId: data.event_id || "unknown",
    network,
    decision: telegramDecision,
    v7,
    fingerprint: data.fingerprint || null,
    policyBaseline,
    monitorDeepInspection: !!data.monitor_deep_inspection,
  });

  const countryLine = `CountryGate: ${data.early_rules?.outcome || "unknown"} stage=${data.early_rules?.stage || "unknown"} reason=${data.early_rules?.reason || "unknown"}`;
  const deviceLine = `DeviceGate: ${data.device_gate?.outcome || "unknown"} stage=${data.device_gate?.stage || "unknown"} reason=${data.device_gate?.reason || "unknown"}`;
  const inspectionLine = data.monitor_deep_inspection
    ? "MonitorDeepInspection: continued through local/fingerprint/AI"
    : "MonitorDeepInspection: policy gates passed normally";

  const currentIpKey = env.DB && env.CHALLENGE_SECRET
    ? await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request))
    : null;
  const alreadyBlocked = currentIpKey
    ? await isManualIpBlocked(env.DB, currentIpKey)
    : false;
  const control = await buildFinalTelegramControl(
    request,
    env,
    alreadyBlocked ? "blocked" : "unblocked",
    data.event_id || null
  );
  const manualLine = control.keyboard
    ? control.eventBound
      ? "ManualIPControl: exact IP — operator feedback learning active"
      : "ManualIPControl: exact IP — Telegram callback BLOCK / UNBLOCK"
    : "ManualIPControl: unavailable";

  waitUntil(
    ctx,
    sendTelegramWithKeyboard(
      env,
      `${telegramCore}\n${countryLine}\n${deviceLine}\n${inspectionLine}\n${manualLine}`,
      control.keyboard
    )
  );

  return {
    keyboardReady: !!control.keyboard,
    webhookConfigured: control.webhookConfigured,
    eventBound: control.eventBound,
  };
}

async function enrichHealth(request, env, ctx) {
  const response = await policyWorker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const state = redirectState(env);
  return Response.json(
    {
      ...data,
      v7_release_mode: "production_redirect_ready",
      v7_redirect_requested: state.requested,
      v7_redirect_enabled: state.enabled,
      v7_redirect_fully_configured: state.fullyConfigured,
      v7_origin_url_configured: state.originConfigured,
      v7_block_url_configured: state.blockConfigured,
      v7_origin_redirect_enabled: state.originEnabled,
      v7_block_redirect_enabled: state.blockEnabled,
      v7_silent_probe_enabled: state.originEnabled && state.blockEnabled,
      v7_silent_probe_strict_hidden: state.originEnabled && state.blockEnabled,
      v7_silent_probe_visible_fallback: false,
      v7_already_blocked_direct_redirect: true,
      v7_already_blocked_visible_page: false,
      v7_telegram_buttons_direct_exact_ip_hmac: true,
      v7_telegram_buttons_browser_independent: true,
      v7_operator_feedback_learning: true,
      v7_operator_feedback_eventref_callback: true,
      v7_operator_block_allow_label: "false_negative",
      v7_operator_feedback_public_training_eligible: false,
      v7_redirect_country_block: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_device_block: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_manual_ip_block: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_human: "ORIGIN_URL",
      v7_redirect_bot_spoof_review: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_loop_guard: true,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function injectRedirectClient(response, env) {
  const contentType = response.headers.get("content-type") || "";
  if (!response.ok || !contentType.includes("text/html")) return response;

  let html;
  try {
    html = await response.text();
  } catch {
    return response;
  }

  const marker = "const data = await response.json();";
  if (!html.includes(marker)) {
    return new Response(html, { status: response.status, headers: response.headers });
  }

  const state = redirectState(env);
  const silentReady = state.originEnabled && state.blockEnabled;
  if (silentReady) html = silentRedirectShell(html);

  const injected = `${marker}\n      if (response.ok && data && data.redirect_enforcing === true && typeof data.redirect_url === \"string\" && data.redirect_url) {\n        window.location.replace(data.redirect_url);\n        return;\n      }`;

  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("referrer-policy", "no-referrer");
  return new Response(html.replace(marker, injected), {
    status: response.status,
    headers,
  });
}

async function handleMonitorPage(request, env, ctx) {
  const response = await policyWorker.fetch(request, env, ctx);

  if (response.status === 404) {
    const redirected = redirectResponse(request, env, "block");
    if (redirected) return redirected;
  }

  return injectRedirectClient(response, env);
}

async function handleFinalSubmit(request, env, ctx) {
  const mutedEnv = {
    ...env,
    TELEGRAM_TOKEN: undefined,
    TELEGRAM_CHAT_ID: undefined,
  };
  const response = await policyWorker.fetch(request, mutedEnv, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  if (data?.status !== "m22_public_monitor_observation") return response;

  const telegram = await sendFinalTelegram(request, env, ctx, data);
  const route = chooseFinalRedirect({
    env,
    requestUrl: request.url,
    monitorDetection: data.monitor_detection || {},
    v7Shadow: data.v7_shadow || null,
  });

  return Response.json(
    {
      ...data,
      telegram_configured: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID,
      telegram_callback_webhook_configured: telegram.webhookConfigured,
      manual_ip_control_ready: telegram.keyboardReady,
      manual_ip_control_event_mapped: telegram.eventBound,
      manual_ip_control_event_bound: telegram.eventBound,
      manual_ip_control_exact_ip: true,
      manual_ip_callback_opens_browser: false,
      redirect_enforcing: route.enabled,
      redirect_action: route.action,
      redirect_reason: route.reason,
      redirect_url: route.url,
      v7_redirect_enforcing: route.enabled,
      ai_bot_enforcing: route.enabled && route.action === "block",
      enforcing: route.enabled,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return enrichHealth(request, env, ctx);
    }

    if (request.method === "GET" && isMonitorPage(url.pathname)) {
      const blocked = await directExactIpBlock(request, env);
      if (blocked) return blocked;
      return handleMonitorPage(request, env, ctx);
    }

    if (url.pathname === "/_shadow/v7-monitor-submit") {
      return handleFinalSubmit(request, env, ctx);
    }

    return policyWorker.fetch(request, env, ctx);
  },
};
