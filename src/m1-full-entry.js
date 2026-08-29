import previousWorker from "./m1-entry.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { insertEvent } from "./storage/d1.js";
import { writeDatasetObject } from "./storage/dataset.js";
import { verifyShadowBrowserToken } from "./compat/v63/shadow-token.js";
import { runV63FullShadowDecision } from "./compat/v63/full-shadow.js";

const VERSION = "V7.0_M1_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

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

    return previousWorker.fetch(request, env, ctx);
  },
};
