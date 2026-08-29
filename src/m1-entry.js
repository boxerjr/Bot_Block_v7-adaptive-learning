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

const VERSION = "V7.0_M1_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Number(value) || 0));
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

async function storeBrowserObservation({
  env,
  network,
  ua,
  telemetry,
  local,
  fingerprint,
  deviceGate,
}) {
  const reasons = [
    ...(Array.isArray(local.reasons) ? local.reasons : []),
    ...(Array.isArray(fingerprint.reasons) ? fingerprint.reasons : []),
  ];

  const combinedRisk = clamp((local.risk || 0) + (fingerprint.risk || 0));
  const wouldBlockBeforeProbe = deviceGate.outcome === "block";

  const event = buildEvent({
    network,
    local: {
      risk: combinedRisk,
      spoofSignals: local.spoofSignals || 0,
      strongHardwareSpoof: !!local.strongHardwareSpoof,
      reasons,
    },
    decision: "unknown",
    finalReasons: [
      "shadow_only",
      "v63_local_plus_fingerprint",
      "real_browser_admin_test",
      wouldBlockBeforeProbe
        ? "v63_would_block_before_probe:desktop_not_allowed"
        : "v63_mobile_gate_pass",
    ],
    telemetrySummary: {
      mode: "shadow",
      baseline: BASELINE,
      source: "real_browser_admin_test",
      dataset_eligible: false,
      raw_ip_stored: false,
      user_agent_stored: false,
      raw_telemetry_stored: false,
      fingerprint_hash_stored_in_dataset: false,
      critical: !!local.critical,
      ua_claim: uaClaimSummary(ua),
      device_gate: {
        outcome: deviceGate.outcome,
        stage: deviceGate.stage,
        reason: deviceGate.reason,
        device: deviceGate.device,
      },
      fingerprint: compactFingerprint(fingerprint),
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
  } catch (error) {
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

  const stored = await storeBrowserObservation({
    env,
    network,
    ua,
    telemetry,
    local,
    fingerprint,
    deviceGate,
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

async function healthWithM1Flags(request, env) {
  const response = await baseWorker.fetch(request, env);

  try {
    const data = await response.clone().json();
    return Response.json(
      {
        ...data,
        v63_mobile_gate_ready: true,
        v63_fingerprint_reputation_ready: true,
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

    return baseWorker.fetch(request, env, ctx);
  },
};
