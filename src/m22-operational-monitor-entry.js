import m22DeepWorker from "./m22-deep-monitor-entry-v2.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { checkMonitorRateLimit } from "./adaptive/monitor-rate-limit.js";
import { deriveMonitorVerdict } from "./adaptive/monitor-verdict.js";
import { buildTelegramDecisionMessage } from "./adaptive/telegram.js";
import {
  clearManualIpBlocked,
  deriveManualIpKey,
  getEventIpKey,
  isManualIpBlocked,
  rememberEventIpKey,
  sendTelegramWithKeyboard,
  setManualIpBlocked,
  verifyManualIpActionToken,
} from "./adaptive/manual-ip-block.js";
import {
  buildTelegramCallbackKeyboard,
  ensureTelegramWebhook,
  handleTelegramCallbackWebhook,
} from "./adaptive/telegram-callback.js";

function waitUntil(ctx, promise) {
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else return promise;
}

function rateLimitPerMinute(env) {
  return Math.max(1, Math.min(120, Number(env.RATE_LIMIT_PER_MIN || 12) || 12));
}

function monitorPageRequest(request) {
  const url = new URL(request.url);
  url.pathname = "/check";
  url.search = "";
  return new Request(url.toString(), request);
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

function htmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function operationalHealth(request, env, ctx) {
  const response = await m22DeepWorker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  return Response.json(
    {
      ...data,
      m22_operational_monitor: true,
      m22_root_monitor_ready: true,
      m22_root_monitor_path: "/",
      m22_check_monitor_path: "/check",
      m22_policy_neutral_verdict_ready: true,
      m22_bot_classes: ["automation", "crawler"],
      m22_spoof_classes: ["spoofed_device"],
      m22_human_classes: ["human_mobile", "human_desktop"],
      m22_review_class: "unknown",
      m22_telegram_final_verdict_ready: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID,
      m22_telegram_callback_buttons_ready: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID && !!env.CHALLENGE_SECRET,
      m22_telegram_callback_opens_browser: false,
      m22_telegram_webhook_path: "/_telegram/webhook",
      m22_rate_limit_ready: !!env.DB && !!env.CHALLENGE_SECRET,
      m22_rate_limit_per_minute_per_network: rateLimitPerMinute(env),
      m22_rate_limit_raw_ip_stored: false,
      m22_manual_ip_control_ready: !!env.DB && !!env.CHALLENGE_SECRET,
      m22_manual_ip_control_exact_ip: true,
      m22_manual_ip_control_raw_ip_stored: false,
      m22_manual_ip_block_enforcing: true,
      m22_automated_enforcing: false,
      m22_enforcing: false,
      m22_dataset_eligible: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function operationalCheck(request, env, ctx) {
  const ip = clientIp(request);

  if (env.DB && env.CHALLENGE_SECRET) {
    const ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, ip);
    if (ipKey && (await isManualIpBlocked(env.DB, ipKey))) {
      return new Response("Not Found", {
        status: 404,
        headers: {
          "cache-control": "no-store",
          "x-robots-tag": "noindex, nofollow",
        },
      });
    }
  }

  const result = await checkMonitorRateLimit({
    db: env.DB,
    secret: env.CHALLENGE_SECRET,
    ip,
    limit: rateLimitPerMinute(env),
  });

  if (!result.allowed) {
    return new Response("Too Many Monitor Requests", {
      status: 429,
      headers: {
        "cache-control": "no-store",
        "retry-after": String(result.retryAfterSeconds || 60),
        "x-robots-tag": "noindex, nofollow",
      },
    });
  }

  return m22DeepWorker.fetch(request, env, ctx);
}

// Kept only so buttons from older Telegram messages still work.
async function handleManualIpAction(request, env, ctx) {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (!env.DB || !env.CHALLENGE_SECRET) {
    return new Response("Manual IP control unavailable.", { status: 503 });
  }

  const token = new URL(request.url).searchParams.get("token") || "";
  const payload = await verifyManualIpActionToken(env.CHALLENGE_SECRET, token);
  if (!payload) {
    return new Response("Invalid or expired action.", {
      status: 401,
      headers: { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" },
    });
  }

  const ipKey = await getEventIpKey(env.DB, payload.event_id);
  if (!ipKey) {
    return new Response("Event IP mapping is no longer available.", {
      status: 404,
      headers: { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" },
    });
  }

  const success = payload.action === "block"
    ? await setManualIpBlocked(env.DB, ipKey, payload.event_id)
    : await clearManualIpBlocked(env.DB, ipKey);

  if (!success) {
    return new Response("Manual IP action failed.", {
      status: 500,
      headers: { "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" },
    });
  }

  const blocked = payload.action === "block";
  const title = blocked ? "🚫 IP BLOCKED" : "🔓 IP UNBLOCKED";
  const telegramText = [
    title,
    `Event: ${String(payload.event_id).slice(0, 8)}`,
    "Scope: exact IP only",
    "Raw IP stored: false",
    blocked ? "Future requests from this exact IP receive 404." : "This exact IP can access the monitor again.",
  ].join("\n");
  waitUntil(ctx, sendTelegramWithKeyboard(env, telegramText, null));

  const heading = blocked ? "🚫 IP blocked" : "🔓 IP unblocked";
  const detail = blocked
    ? "Future requests from this exact IP will receive HTTP 404 on the V7 test monitor."
    : "This exact IP can access the V7 test monitor again.";

  return new Response(
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>V7 Manual IP Control</title></head><body style="font-family:system-ui;padding:32px;max-width:720px;margin:auto"><h1>${htmlEscape(heading)}</h1><p>${htmlEscape(detail)}</p><p>Exact-IP HMAC match; raw IP is not stored.</p></body></html>`,
    {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-robots-tag": "noindex, nofollow",
        "referrer-policy": "no-referrer",
      },
    }
  );
}

async function operationalSubmit(request, env, ctx) {
  const mutedEnv = {
    ...env,
    TELEGRAM_TOKEN: undefined,
    TELEGRAM_CHAT_ID: undefined,
  };

  const response = await m22DeepWorker.fetch(request, mutedEnv, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  if (data?.status !== "m22_public_monitor_observation") {
    return response;
  }

  const v63Decision = rebuildDecision(data);
  const monitorVerdict = deriveMonitorVerdict(v63Decision);
  const policyBaseline = rebuildPolicy(data);
  const v7 = rebuildV7(data);
  const network = networkInfo(request);

  const telegramDecision = {
    ...v63Decision,
    finalDecision: monitorVerdict.decision,
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

  let manualIpMapped = false;
  let manualKeyboard = null;
  let telegramWebhookConfigured = false;
  if (env.DB && env.CHALLENGE_SECRET && data.event_id) {
    try {
      const ipKey = await deriveManualIpKey(env.CHALLENGE_SECRET, clientIp(request));
      manualIpMapped = !!ipKey && await rememberEventIpKey(env.DB, data.event_id, ipKey);
      if (manualIpMapped) {
        const webhook = await ensureTelegramWebhook(env, request.url);
        telegramWebhookConfigured = webhook.configured === true;
        if (telegramWebhookConfigured) {
          manualKeyboard = await buildTelegramCallbackKeyboard(
            env.CHALLENGE_SECRET,
            data.event_id,
            "unblocked"
          );
        }
      }
    } catch {}
  }

  const manualLine = manualIpMapped && telegramWebhookConfigured
    ? "ManualIPControl: exact IP — Telegram callback BLOCK / UNBLOCK"
    : "ManualIPControl: unavailable";

  waitUntil(
    ctx,
    sendTelegramWithKeyboard(
      env,
      `${telegramCore}\n${countryLine}\n${deviceLine}\n${inspectionLine}\n${manualLine}`,
      manualKeyboard
    )
  );

  const monitorDetection = {
    final_decision: monitorVerdict.decision,
    would_block: monitorVerdict.decision === "block",
    classification: monitorVerdict.classification,
    confidence: Number(monitorVerdict.confidence || 0),
    risk: Number(monitorVerdict.risk || 0),
    reasons: Array.isArray(monitorVerdict.reasons) ? monitorVerdict.reasons : [],
  };

  return Response.json(
    {
      ...data,
      telegram_configured: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID,
      telegram_callback_webhook_configured: telegramWebhookConfigured,
      v63_detection: {
        final_decision: data.final_decision,
        would_block: !!data.would_block,
        decision_stage: data.decision_stage,
      },
      monitor_detection: monitorDetection,
      monitor_verdict: monitorVerdict,
      monitor_final_decision: monitorVerdict.decision,
      monitor_is_bot: ["automation", "crawler"].includes(monitorVerdict.classification),
      monitor_is_spoof: monitorVerdict.classification === "spoofed_device",
      manual_ip_control_ready: manualIpMapped && telegramWebhookConfigured,
      manual_ip_control_exact_ip: true,
      manual_ip_callback_opens_browser: false,
      manual_ip_raw_stored: false,
      automated_enforcing: false,
      manual_ip_block_enforcing: true,
      enforcing: false,
      dataset_eligible: false,
      training_eligible: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return operationalHealth(request, env, ctx);
    }
    if (url.pathname === "/_telegram/webhook") {
      return handleTelegramCallbackWebhook(request, env);
    }
    if (url.pathname === "/_telegram/ip-action") {
      return handleManualIpAction(request, env, ctx);
    }
    if (url.pathname === "/" || url.pathname === "") {
      return operationalCheck(monitorPageRequest(request), env, ctx);
    }
    if (url.pathname === "/check" || url.pathname === "/check/") {
      return operationalCheck(request, env, ctx);
    }
    if (url.pathname === "/_shadow/v7-monitor-submit") {
      return operationalSubmit(request, env, ctx);
    }

    return m22DeepWorker.fetch(request, env, ctx);
  },
};
