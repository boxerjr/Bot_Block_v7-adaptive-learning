import baseWorker from "./index.js";
import { boolEnv } from "./engine/config.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { insertEvent } from "./storage/d1.js";
import { writeDatasetObject } from "./storage/dataset.js";
import { evaluateV63MobileGate } from "./compat/v63/device.js";
import { fingerprintV63Reputation } from "./compat/v63/fingerprint.js";
import { scoreV63Signals } from "./compat/v63/score-signals.js";
import { verifyShadowBrowserToken } from "./compat/v63/shadow-token.js";
import {
  buildV63AiFeatures,
  runV63AiPipeline,
} from "./compat/v63/ai.js";

const VERSION = "V7.0_M1_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
}

function adminAuthorized(request, env) {
  const direct = request.headers.get("x-admin-secret") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ")
    ? auth.slice(7).trim()
    : "";
  const supplied = direct || bearer;
  return !!env.ADMIN_SECRET && supplied === env.ADMIN_SECRET;
}

function uaClaimSummary(ua = "") {
  const value = String(ua);
  const ios = /(iphone|ipad|ipod)/i.test(value);
  const android = /android/i.test(value);
  return {
    mobile: ios || android || /mobile/i.test(value),
    android,
    ios,
  };
}

function compactFingerprint(fp) {
  return {
    recentNetworks: fp?.recentNetworks || 0,
    seen: fp?.seen || 0,
    risk: fp?.risk || 0,
    reasons: Array.isArray(fp?.reasons) ? fp.reasons : [],
    stored: fp?.stored === true,
  };
}

function compactAiPipeline(aiPipeline, skippedReason = null) {
  if (skippedReason) {
    return {
      run: false,
      critic_run: false,
      skipped_reason: skippedReason,
      would_block: false,
      final_reasons: [],
      human_evidence: 0,
      error: null,
    };
  }

  return {
    run: !!aiPipeline?.runAi,
    critic_run: !!aiPipeline?.criticRun,
    skipped_reason: null,
    would_block: !!aiPipeline?.wouldBlock,
    final_reasons: Array.isArray(aiPipeline?.finalReasons)
      ? aiPipeline.finalReasons
      : [],
    human_evidence: Number(aiPipeline?.humanEvidence || 0),
    error: aiPipeline?.error || null,
  };
}

async function storeBrowserObservation({
  env,
  network,
  ua,
  telemetry,
  local,
  fingerprint,
  deviceGate,
  aiPipeline = null,
  aiSkippedReason = null,
}) {
  const reasons = [
    ...(Array.isArray(local.reasons) ? local.reasons : []),
    ...(Array.isArray(fingerprint.reasons) ? fingerprint.reasons : []),
  ];

  const combinedRisk = clamp((local.risk || 0) + (fingerprint.risk || 0));
  const wouldBlockBeforeProbe = deviceGate.outcome === "block";
  const aiSummary = compactAiPipeline(aiPipeline, aiSkippedReason);

  const finalReasons = [
    "shadow_only",
    "v63_local_plus_fingerprint",
    "real_browser_admin_test",
    wouldBlockBeforeProbe
      ? "v63_would_block_before_probe:desktop_not_allowed"
      : "v63_mobile_gate_pass",
  ];

  if (aiSkippedReason) {
    finalReasons.push(`ai_shadow_skipped:${aiSkippedReason}`);
  } else if (aiPipeline?.wouldBlock) {
    finalReasons.push("ai_shadow_would_block");
    finalReasons.push(...(aiPipeline.finalReasons || []));
  } else if (aiPipeline?.runAi) {
    finalReasons.push("ai_shadow_allow");
  }

  const event = buildEvent({
    network,
    local: {
      risk: combinedRisk,
      spoofSignals: local.spoofSignals || 0,
      strongHardwareSpoof: !!local.strongHardwareSpoof,
      reasons,
    },
    ai1: aiPipeline?.ai || null,
    ai2: aiPipeline?.critic || null,
    decision: "unknown",
    finalReasons,
    telemetrySummary: {
      mode: "shadow",
      baseline: BASELINE,
      source: "real_browser_admin_test",
      dataset_eligible: false,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      fingerprint_hash_stored_in_dataset: false,
      ai_features_stored: false,
      critical: !!local.critical,
      ua_claim: uaClaimSummary(ua),
      device_gate: {
        outcome: deviceGate.outcome,
        stage: deviceGate.stage,
        reason: deviceGate.reason,
        device: deviceGate.device,
      },
      fingerprint: compactFingerprint(fingerprint),
      ai_shadow: aiSummary,
      telemetry_sections: {
        navigator: !!telemetry.navigator,
        ua_data: !!telemetry.uaData,
        media: !!telemetry.media,
        webgl: !!telemetry.webgl,
        webgpu: !!telemetry.webgpu,
        automation: !!telemetry.automation,
        capabilities: !!telemetry.capabilities,
        interaction: !!telemetry.interaction,
      },
    },
  });

  const [d1Result, r2Result] = await Promise.allSettled([
    insertEvent(env.DB, event),
    writeDatasetObject(env.DATASET, event, { prefix: "tests/browser" }),
  ]);

  return {
    event,
    combinedRisk,
    reasons,
    d1Result,
    r2Result,
    d1Written: d1Result.status === "fulfilled",
    r2Written: r2Result.status === "fulfilled",
    wouldBlockBeforeProbe,
    aiSummary,
  };
}

async function handleBrowserProbeSubmit(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }

  if (!env.CHALLENGE_SECRET) {
    return Response.json({ error: "challenge_secret_missing" }, { status: 503 });
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > 120000) {
    return Response.json({ error: "payload_too_large" }, { status: 413 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }

  const tokenPayload = await verifyShadowBrowserToken(
    env.CHALLENGE_SECRET,
    body?.token || ""
  );

  if (!tokenPayload) {
    return Response.json({ error: "invalid_or_expired_probe_token" }, { status: 401 });
  }

  const telemetry =
    body?.telemetry && typeof body.telemetry === "object" ? body.telemetry : {};
  const ua = request.headers.get("user-agent") || "";
  const network = networkInfo(request);
  const ip = clientIp(request);

  const deviceGate = evaluateV63MobileGate({
    ua,
    chMobile: request.headers.get("sec-ch-ua-mobile"),
    mobileOnly: boolEnv(env.MOBILE_ONLY, true),
  });

  const local = scoreV63Signals({ request, env, network, ua, telemetry });

  let fingerprint;
  try {
    fingerprint = await fingerprintV63Reputation({
      db: env.DB,
      ip,
      ua,
      network,
      telemetry,
    });
  } catch {
    fingerprint = {
      fpHash: null,
      recentNetworks: 0,
      seen: 0,
      risk: 0,
      reasons: [],
      stored: false,
      reason: "fingerprint_state_error",
    };
  }

  const combinedLocal = {
    ...local,
    risk: clamp((local.risk || 0) + (fingerprint.risk || 0)),
    reasons: [
      ...(Array.isArray(local.reasons) ? local.reasons : []),
      ...(Array.isArray(fingerprint.reasons) ? fingerprint.reasons : []),
    ],
  };

  let aiPipeline = null;
  let aiSkippedReason = null;

  if (deviceGate.outcome === "block") {
    aiSkippedReason = "desktop_not_allowed";
  } else {
    const features = buildV63AiFeatures({
      request,
      env,
      network,
      ua,
      telemetry,
      local: combinedLocal,
      fingerprint,
    });

    aiPipeline = await runV63AiPipeline({
      env,
      features,
      local: combinedLocal,
    });
  }

  const stored = await storeBrowserObservation({
    env,
    network,
    ua,
    telemetry,
    local,
    fingerprint,
    deviceGate,
    aiPipeline,
    aiSkippedReason,
  });

  return Response.json(
    {
      status:
        stored.d1Written && stored.r2Written
          ? "v63_real_browser_observation_stored"
          : "v63_real_browser_observation_partial",
      version: VERSION,
      baseline: BASELINE,
      enforcing: false,
      event_id: stored.event.event_id,
      d1_written: stored.d1Written,
      r2_written: stored.r2Written,
      r2_key:
        stored.r2Result.status === "fulfilled" ? stored.r2Result.value : null,
      dataset_eligible: false,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      would_block_before_probe: stored.wouldBlockBeforeProbe,
      device_gate: {
        outcome: deviceGate.outcome,
        stage: deviceGate.stage,
        reason: deviceGate.reason,
        device: deviceGate.device,
      },
      fingerprint: compactFingerprint(fingerprint),
      ai_shadow: stored.aiSummary,
      ai1: aiPipeline?.ai || null,
      ai2: aiPipeline?.critic || null,
      result: {
        risk: stored.combinedRisk,
        localRiskBeforeFingerprint: local.risk,
        fingerprintRisk: fingerprint.risk || 0,
        spoofSignals: local.spoofSignals || 0,
        strongHardwareSpoof: !!local.strongHardwareSpoof,
        critical: !!local.critical,
        reasons: stored.reasons,
      },
    },
    { status: stored.d1Written && stored.r2Written ? 201 : 500 }
  );
}

function diagnosticProfile(name) {
  if (name === "spoof_mobile") {
    const ua =
      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36";
    return {
      ua,
      headers: {
        "user-agent": ua,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "accept-language": "en-US,en;q=0.9",
      },
      network: {
        country: "ES",
        asn: "AS14593",
        org: "M1 synthetic safe ASN",
        httpProtocol: "HTTP/3",
        tlsVersion: "TLSv1.3",
        bot: null,
      },
      telemetry: {
        navigator: {
          userAgent: ua,
          platform: "Win32",
          vendor: "Google Inc.",
          maxTouchPoints: 0,
          hardwareConcurrency: 32,
          deviceMemory: 8,
          webdriver: false,
        },
        uaData: { present: true, mobile: false, architecture: "x86_64" },
        media: { pointerFine: true, pointerCoarse: false, anyHoverHover: true },
        webgl: { vendor: "NVIDIA", renderer: "NVIDIA GeForce RTX 4090" },
        webgpu: { vendor: "NVIDIA", description: "NVIDIA GeForce RTX 4090", architecture: "x86_64" },
        automation: {},
      },
      local: {
        risk: 75,
        critical: false,
        spoofSignals: 8,
        strongHardwareSpoof: true,
        reasons: ["m1_synthetic_strong_hardware_spoof"],
      },
      fingerprint: { recentNetworks: 1, seen: 1, risk: 0 },
    };
  }

  const ua =
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36";
  return {
    ua,
    headers: {
      "user-agent": ua,
      "sec-ch-ua-mobile": "?1",
      "sec-ch-ua-platform": '"Android"',
      "accept-language": "en-US,en;q=0.9",
    },
    network: {
      country: "ES",
      asn: "AS14593",
      org: "M1 synthetic safe ASN",
      httpProtocol: "HTTP/3",
      tlsVersion: "TLSv1.3",
      bot: null,
    },
    telemetry: {
      navigator: {
        userAgent: ua,
        platform: "Linux armv8l",
        vendor: "Google Inc.",
        maxTouchPoints: 5,
        hardwareConcurrency: 8,
        deviceMemory: 8,
        webdriver: false,
      },
      uaData: { present: true, mobile: true, architecture: "arm" },
      media: { pointerFine: false, pointerCoarse: true, anyHoverHover: false },
      webgl: { vendor: "Qualcomm", renderer: "Adreno 750" },
      webgpu: { vendor: "Qualcomm", description: "Adreno 750", architecture: "arm" },
      automation: {},
    },
    local: {
      risk: 0,
      critical: false,
      spoofSignals: 0,
      strongHardwareSpoof: false,
      reasons: ["safe_access_asn"],
    },
    fingerprint: { recentNetworks: 1, seen: 1, risk: 0 },
  };
}

async function handleAiDiagnostic(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!adminAuthorized(request, env)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  if (!env.AI) {
    return Response.json({ error: "ai_binding_missing" }, { status: 503 });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {}

  const profileName = body?.profile === "spoof_mobile" ? "spoof_mobile" : "human_mobile";
  const profile = diagnosticProfile(profileName);
  const syntheticRequest = new Request(request.url, { headers: profile.headers });
  const features = buildV63AiFeatures({
    request: syntheticRequest,
    env,
    network: profile.network,
    ua: profile.ua,
    telemetry: profile.telemetry,
    local: profile.local,
    fingerprint: profile.fingerprint,
  });

  const pipeline = await runV63AiPipeline({ env, features, local: profile.local });

  return Response.json({
    status: "v63_ai_shadow_diagnostic",
    version: VERSION,
    baseline: BASELINE,
    enforcing: false,
    dataset_eligible: false,
    profile: profileName,
    model: env.AI_MODEL || "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    ai_schema: "confidence_v2",
    ai_run: pipeline.runAi,
    critic_run: pipeline.criticRun,
    ai1: pipeline.ai,
    ai2: pipeline.critic,
    would_block: pipeline.wouldBlock,
    final_reasons: pipeline.finalReasons,
    human_evidence: pipeline.humanEvidence,
    error: pipeline.error,
  });
}

async function healthWithM1Flags(request, env) {
  const response = await baseWorker.fetch(request, env);

  try {
    const data = await response.clone().json();
    return Response.json(
      {
        ...data,
        v63_mobile_gate_ready: true,
        v63_fingerprint_reputation_ready: true,
        v63_ai_confidence_v2_ready: true,
        v63_ai_shadow_diagnostic_ready: true,
      },
      {
        status: response.status,
        headers: { "cache-control": "no-store" },
      }
    );
  } catch {
    return response;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return healthWithM1Flags(request, env);
    }

    if (url.pathname === "/_shadow/browser-probe-submit") {
      return handleBrowserProbeSubmit(request, env);
    }

    if (url.pathname === "/_shadow/v63-ai-test") {
      return handleAiDiagnostic(request, env);
    }

    return baseWorker.fetch(request, env, ctx);
  },
};
