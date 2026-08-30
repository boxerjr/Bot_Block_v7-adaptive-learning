import { classifyOrganization } from "./org-intelligence.js";

function clean(value, max = 180) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, max);
}

export function coarseUaFamily(ua = "") {
  const value = String(ua).toLowerCase();
  if (/googlebot|bingbot|duckduckbot|yandexbot|baiduspider/.test(value)) return "crawler";
  if (/headlesschrome|phantomjs|selenium|playwright|puppeteer/.test(value)) return "automation";
  if (/samsungbrowser/.test(value)) return "android_samsung_browser";
  if (/iphone|ipad|ipod/.test(value)) return "ios_browser";
  if (/android/.test(value)) return "android_browser";
  if (/edg\//.test(value)) return "desktop_edge";
  if (/firefox\//.test(value)) return "desktop_firefox";
  if (/chrome\//.test(value)) return "desktop_chrome";
  if (/safari\//.test(value)) return "desktop_safari";
  return "unknown";
}

function verdictIcon(detection, v7, classification = "", policyNeutral = false) {
  const cls = String(classification || "").toLowerCase();

  if (policyNeutral) {
    if (cls === "automation" || cls === "crawler") return "🤖 BOT_SHADOW";
    if (cls === "spoofed_device") return "🎭 SPOOF_SHADOW";
    if (cls === "human_desktop") return "🖥️ HUMAN_DESKTOP";
    if (cls === "human_mobile") return "👤 HUMAN_PASS";
    if (detection === "review" || detection === "block") return "⚠️ REVIEW_SHADOW";
    return "👤 HUMAN_PASS";
  }

  if (detection === "block" || v7 === "block") return "🤖 BOT_SHADOW";
  if (detection === "review" || v7 === "review") return "⚠️ REVIEW_SHADOW";
  return "👤 HUMAN_PASS";
}

function orgIntelLine(network = {}) {
  const intel = classifyOrganization(network.org);
  return `OrgIntel: ${clean(intel.class)} conf=${Number(intel.confidence || 0)} riskDelta=${Number(intel.riskDelta || 0)} rule=${clean(intel.matchedRule || "none")}`;
}

export function buildTelegramHitMessage({ sessionId, network = {}, early = {}, uaFamily = "unknown" }) {
  const earlyState = early?.outcome === "block"
    ? `would_block:${clean(early.reason || early.stage)}`
    : "continue";

  return [
    "🌐 TRAFFIC_HIT",
    `Session: ${clean(String(sessionId || "").slice(0, 8))}`,
    `Country: ${clean(network.country || "?")}`,
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    orgIntelLine(network),
    `UAFamily: ${clean(uaFamily)}`,
    `EarlyPolicy: ${earlyState}`,
    "Mode: shadow / deep inspection / no enforcement / no training",
  ].join("\n");
}

export function buildTelegramDecisionMessage({
  sessionId,
  network = {},
  decision = {},
  v7 = null,
  fingerprint = null,
  policyBaseline = null,
  monitorDeepInspection = false,
  enforcing = false,
  enforcementAction = null,
}) {
  const ai1 = decision.ai?.ai || null;
  const ai2 = decision.ai?.critic || null;
  const monitorVerdict = decision.monitorVerdict || null;
  const policyNeutral = decision.decisionStage === "monitor_policy_neutral" || !!monitorVerdict;
  const title = verdictIcon(
    monitorVerdict?.decision || decision.finalDecision,
    v7?.v7Decision,
    monitorVerdict?.classification || "",
    policyNeutral
  );

  const lines = [
    title,
    `Session: ${clean(String(sessionId || "").slice(0, 8))}`,
    `Country: ${clean(network.country || "?")}`,
    `ASN: ${clean(network.asn || "?")}`,
    `Org: ${clean(network.org || "?")}`,
    orgIntelLine(network),
  ];

  if (policyBaseline) {
    lines.push(
      `PolicyV6.3: ${clean(policyBaseline.finalDecision || "unknown")} stage=${clean(policyBaseline.decisionStage || "unknown")} reason=${clean(policyBaseline.reason || "-")}`,
      `PolicyWouldBlock: ${!!policyBaseline.wouldBlock}`,
      `MonitorDeepInspection: ${!!monitorDeepInspection}`
    );
  }

  if (monitorVerdict) {
    lines.push(
      `MonitorDetection: ${clean(monitorVerdict.decision)} class=${clean(monitorVerdict.classification)} conf=${Number(monitorVerdict.confidence || 0)} risk=${Number(monitorVerdict.risk || 0)}`
    );
    if (Array.isArray(monitorVerdict.reasons) && monitorVerdict.reasons.length) {
      lines.push(`DetectionReasons: ${clean(monitorVerdict.reasons.join(", "), 360)}`);
    }
  } else {
    lines.push(
      `MonitorDetection: ${clean(decision.finalDecision || "unknown")} stage=${clean(decision.decisionStage || "unknown")}`
    );
  }

  lines.push(
    `LocalRisk: ${Number(decision.local?.risk || 0)}`,
    `SpoofSignals: ${Number(decision.local?.spoofSignals || 0)}`,
    `StrongHardwareSpoof: ${!!decision.local?.strongHardwareSpoof}`
  );

  if (ai1) {
    lines.push(
      `AI1(V6.3): ${clean(ai1.verdict || "?")} class=${clean(ai1.classification || "?")} conf=${Number(ai1.classification_confidence || 0)} human=${Number(ai1.human_probability || 0)} bot=${Number(ai1.bot_probability || 0)} spoof=${Number(ai1.spoof_probability || 0)} risk=${Number(ai1.risk_score || 0)}`
    );
  } else {
    lines.push("AI1(V6.3): not-run");
  }

  if (ai2) {
    lines.push(
      `AI2(V6.3): ${clean(ai2.verdict || "?")} class=${clean(ai2.classification || "?")} conf=${Number(ai2.classification_confidence || 0)} human=${Number(ai2.human_probability || 0)} bot=${Number(ai2.bot_probability || 0)} spoof=${Number(ai2.spoof_probability || 0)} risk=${Number(ai2.risk_score || 0)}`
    );
  } else {
    lines.push("AI2(V6.3): not-run");
  }

  lines.push(`HumanEvidence(V6.3): ${Number(decision.ai?.humanEvidence || 0)}`);

  if (v7) {
    lines.push(
      `V7Compat: ${clean(v7.v7Decision || "unknown")} risk=${Number(v7.v7Risk || 0)} base=${Number(v7.baseRisk || 0)} asnAdj=${Number(v7.asnAdjustment || 0)} fpAdj=${Number(v7.fingerprintAdjustment || 0)} comparison=${clean(v7.comparison || "?")}`
    );
  }

  if (fingerprint) {
    lines.push(
      `FPNetworks: ${Number(fingerprint.recentNetworks || 0)} seen=${Number(fingerprint.seen || 0)} risk=${Number(fingerprint.risk || 0)}`
    );
  }

  lines.push(
    "DatasetEligible: false",
    enforcing
      ? `Enforcing: true action=${clean(enforcementAction || "unknown")}`
      : "Enforcing: false",
    "RawIP/UA stored: false"
  );
  return lines.join("\n").slice(0, 3900);
}

export async function sendTelegram(env, text) {
  const token = env?.TELEGRAM_TOKEN;
  const chatId = env?.TELEGRAM_CHAT_ID;
  if (!token || !chatId || !text) return { sent: false, reason: "telegram_not_bound" };

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: String(chatId),
        text: String(text).slice(0, 3900),
        disable_web_page_preview: true,
      }),
    });
    return { sent: response.ok, status: response.status };
  } catch (error) {
    return {
      sent: false,
      reason: "telegram_fetch_error",
      error: String(error?.message || error).slice(0, 120),
    };
  }
}
