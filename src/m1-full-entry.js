import previousWorker from "./m1-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { insertEvent } from "./storage/d1.js";
import { writeDatasetObject } from "./storage/dataset.js";
import { verifyShadowBrowserToken } from "./compat/v63/shadow-token.js";
import { runV63FullShadowDecision } from "./compat/v63/full-shadow.js";

const VERSION = "V7.0_M1_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

function adminAuthorized(request, env) {
  const direct = request.headers.get("x-admin-secret") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ")
    ? auth.slice(7).trim()
    : "";
  const supplied = direct || bearer;
  return !!env.ADMIN_SECRET && supplied === env.ADMIN_SECRET;
}

function compactFingerprint(fp) {
  return {
    recentNetworks: Number(fp?.recentNetworks || 0),
    seen: Number(fp?.seen || 0),
    risk: Number(fp?.risk || 0),
    reasons: Array.isArray(fp?.reasons) ? fp.reasons : [],
    stored: fp?.stored === true,
    reason: fp?.reason || null,
  };
}

function compactGate(gate) {
  if (!gate) return null;
  return {
    outcome: gate.outcome,
    stage: gate.stage,
    reason: gate.reason,
    device: gate.device || null,
  };
}

function compactEarly(early) {
  if (!early) return null;
  return {
    outcome: early.outcome,
    stage: early.stage,
    reason: early.reason,
  };
}

function compactAi(ai) {
  if (!ai) return null;
  return {
    run: !!ai.runAi,
    critic_run: !!ai.criticRun,
    skipped_reason: ai.skippedReason || null,
    ai1: ai.ai || null,
    ai2: ai.critic || null,
    human_evidence: Number(ai.humanEvidence || 0),
    hard_local_block: !!ai.hardLocalBlock,
    error: ai.error || null,
  };
}

function fullDiagnosticProfile(name) {
  const ua =
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36";

  if (name === "spoof_mobile") {
    return {
      ua,
      headers: {
        "user-agent": ua,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "accept-language": "es-ES,es;q=0.9,en;q=0.8",
      },
      network: {
        country: "ES",
        asn: "AS14593",
        org: "M1 synthetic safe ASN",
        httpProtocol: "HTTP/3",
        tlsVersion: "TLSv1.3",
        bot: {},
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
        uaData: {
          present: true,
          mobile: false,
          platform: "Windows",
          architecture: "x86_64",
        },
        media: {
          pointerFine: true,
          pointerCoarse: false,
          anyHoverHover: true,
        },
        webgl: {
          vendor: "NVIDIA Corporation",
          renderer: "NVIDIA GeForce RTX 4090",
        },
        webgpu: {
          vendor: "NVIDIA",
          description: "NVIDIA GeForce RTX 4090",
          architecture: "x86_64",
        },
        automation: {
          selenium: false,
          phantom: false,
          nightmare: false,
          webdriverAttr: false,
          cdc: false,
        },
      },
      syntheticIp: "198.51.100.20",
    };
  }

  return {
    ua,
    headers: {
      "user-agent": ua,
      "sec-ch-ua-mobile": "?1",
      "sec-ch-ua-platform": '"Android"',
      "accept-language": "es-ES,es;q=0.9,en;q=0.8",
    },
    network: {
      country: "ES",
      asn: "AS14593",
      org: "M1 synthetic safe ASN",
      httpProtocol: "HTTP/3",
      tlsVersion: "TLSv1.3",
      bot: {},
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
      uaData: {
        present: true,
        mobile: true,
        platform: "Android",
        architecture: "arm",
      },
      media: {
        pointerFine: false,
        pointerCoarse: true,
        anyHoverHover: false,
      },
      webgl: {
        vendor: "Qualcomm",
        renderer: "Adreno 750",
      },
      webgpu: {
        vendor: "Qualcomm",
        description: "Adreno 750",
        architecture: "arm",
      },
      automation: {
        selenium: false,
        phantom: false,
        nightmare: false,
        webdriverAttr: false,
        cdc: false,
      },
    },
    syntheticIp: "198.51.100.10",
  };
}

async function handleFullDiagnostic(request, env) {
  if (request.method !== "POST") {
    return Response.json({ error: "method_not_allowed" }, { status: 405 });
  }
  if (!adminAuthorized(request, env)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  let body = {};
  try {
    body = await request.json();
  } catch {}

  const profileName = body?.profile === "spoof_mobile"
    ? "spoof_mobile"
    : "human_mobile";
  const profile = fullDiagnosticProfile(profileName);
  const syntheticRequest = new Request(request.url, {
    method: "GET",
    headers: profile.headers,
  });

  const decision = await runV63FullShadowDecision({
    request: syntheticRequest,
    env,
    network: profile.network,
    ip: profile.syntheticIp,
    ua: profile.ua,
    telemetry: profile.telemetry,
    targetPath: "/",
  });

  return Response.json({
    status: "v63_full_shadow_diagnostic",
    version: VERSION,
    baseline: BASELINE,
    enforcing: false,
    dataset_eligible: false,
    profile: profileName,
    final_decision: decision.finalDecision,
    would_block: decision.finalDecision === "block",
    decision_stage: decision.decisionStage,
    final_reasons: decision.finalReasons,
    early_rules: compactEarly(decision.early),
    device_gate: compactGate(decision.deviceGate),
    fingerprint: compactFingerprint(decision.fingerprint),
    local: {
      risk: Number(decision.local?.risk || 0),
      spoofSignals: Number(decision.local?.spoofSignals || 0),
      strongHardwareSpoof: !!decision.local?.strongHardwareSpoof,
      critical: !!decision.local?.critical,
      reasons: Array.isArray(decision.local?.reasons) ? decision.local.reasons : [],
    },
    ai: compactAi(decision.ai),
    persisted_event: false,
    raw_ip_stored: false,
    user_agent_stored: false,
    raw_telemetry_stored: false,
  });
}

async function handleFullBrowserSubmit(request, env) {
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

  const decision = await runV63FullShadowDecision({
    request,
    env,
    network,
    ip,
    ua,
    telemetry,
    targetPath: "/",
  });

  const event = buildEvent({
    network,
    local: {
      risk: decision.local.risk,
      spoofSignals: decision.local.spoofSignals,
      strongHardwareSpoof: decision.local.strongHardwareSpoof,
      reasons: decision.local.reasons,
    },
    ai1: decision.ai?.ai || null,
    ai2: decision.ai?.critic || null,
    decision: decision.finalDecision,
    finalReasons: [
      "shadow_only",
      "v63_full_decision",
      ...decision.finalReasons,
    ],
    telemetrySummary: {
      mode: "shadow",
      baseline: BASELINE,
      source: "real_browser_full_v63_shadow",
      dataset_eligible: false,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      fingerprint_hash_stored_in_dataset: false,
      target_path: "/",
      decision_stage: decision.decisionStage,
      early_rules: compactEarly(decision.early),
      device_gate: compactGate(decision.deviceGate),
      fingerprint: compactFingerprint(decision.fingerprint),
      ai: {
        run: !!decision.ai?.runAi,
        critic_run: !!decision.ai?.criticRun,
        skipped_reason: decision.ai?.skippedReason || null,
        human_evidence: Number(decision.ai?.humanEvidence || 0),
        hard_local_block: !!decision.ai?.hardLocalBlock,
        error_present: !!decision.ai?.error,
      },
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
    writeDatasetObject(env.DATASET, event, { prefix: "tests/browser/full" }),
  ]);

  const d1Written = d1Result.status === "fulfilled";
  const r2Written = r2Result.status === "fulfilled";

  return Response.json(
    {
      status:
        d1Written && r2Written
          ? "v63_full_shadow_decision_stored"
          : "v63_full_shadow_decision_partial",
      version: VERSION,
      baseline: BASELINE,
      enforcing: false,
      event_id: event.event_id,
      d1_written: d1Written,
      r2_written: r2Written,
      r2_key: r2Written ? r2Result.value : null,
      dataset_eligible: false,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      final_decision: decision.finalDecision,
      would_block: decision.finalDecision === "block",
      decision_stage: decision.decisionStage,
      final_reasons: decision.finalReasons,
      early_rules: compactEarly(decision.early),
      device_gate: compactGate(decision.deviceGate),
      fingerprint: compactFingerprint(decision.fingerprint),
      local: {
        risk: Number(decision.local.risk || 0),
        spoofSignals: Number(decision.local.spoofSignals || 0),
        strongHardwareSpoof: !!decision.local.strongHardwareSpoof,
        critical: !!decision.local.critical,
        reasons: Array.isArray(decision.local.reasons) ? decision.local.reasons : [],
      },
      ai: compactAi(decision.ai),
    },
    { status: d1Written && r2Written ? 201 : 500 }
  );
}

async function healthWithFullFlag(request, env, ctx) {
  const response = await previousWorker.fetch(request, env, ctx);

  try {
    const data = await response.clone().json();
    return Response.json(
      {
        ...data,
        v63_full_shadow_decision_ready: true,
        v63_full_shadow_diagnostic_ready: true,
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
      return healthWithFullFlag(request, env, ctx);
    }

    if (url.pathname === "/_shadow/browser-probe-submit") {
      return handleFullBrowserSubmit(request, env);
    }

    if (url.pathname === "/_shadow/v63-full-test") {
      return handleFullDiagnostic(request, env);
    }

    return previousWorker.fetch(request, env, ctx);
  },
};
