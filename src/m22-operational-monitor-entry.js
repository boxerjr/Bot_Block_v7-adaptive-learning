import m22DeepWorker from "./m22-deep-monitor-entry-v2.js";
import { networkInfo } from "./engine/network.js";
import { deriveMonitorVerdict } from "./adaptive/monitor-verdict.js";
import {
  buildTelegramDecisionMessage,
  sendTelegram,
} from "./adaptive/telegram.js";

function waitUntil(ctx, promise) {
  if (ctx?.waitUntil) ctx.waitUntil(promise);
  else return promise;
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
      m22_policy_neutral_verdict_ready: true,
      m22_bot_classes: ["automation", "crawler"],
      m22_spoof_classes: ["spoofed_device"],
      m22_human_classes: ["human_mobile", "human_desktop"],
      m22_review_class: "unknown",
      m22_telegram_final_verdict_ready: !!env.TELEGRAM_TOKEN && !!env.TELEGRAM_CHAT_ID,
      m22_enforcing: false,
      m22_dataset_eligible: false,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function operationalSubmit(request, env, ctx) {
  // Suppress the older final Telegram message. The page-hit Telegram notification
  // is unaffected because only this submit path is wrapped with muted credentials.
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

  waitUntil(
    ctx,
    sendTelegram(
      env,
      `${telegramCore}\n${countryLine}\n${deviceLine}\n${inspectionLine}`
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
    if (url.pathname === "/_shadow/v7-monitor-submit") {
      return operationalSubmit(request, env, ctx);
    }

    return m22DeepWorker.fetch(request, env, ctx);
  },
};
