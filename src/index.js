import { csvSet, boolEnv } from "./engine/config.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { insertEvent } from "./storage/d1.js";
import { writeDatasetObject } from "./storage/dataset.js";
import { evaluateV63EarlyRules } from "./compat/v63/preflight.js";
import { scoreV63Signals } from "./compat/v63/score-signals.js";

const VERSION = "V7.0_M1_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

function adminAuthorized(request, env) {
  const direct = request.headers.get("x-admin-secret") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const network = networkInfo(request);

    if (url.pathname === "/_health") {
      return Response.json({
        status: "ok",
        version: VERSION,
        phase: "m1-shadow",
        baseline: BASELINE,
        country: network.country,
        asn: network.asn,
        ai_bound: !!env.AI,
        d1_bound: !!env.DB,
        r2_bound: !!env.DATASET,
        admin_secret_bound: !!env.ADMIN_SECRET,
        challenge_secret_bound: !!env.CHALLENGE_SECRET,
        shadow_storage_test_ready: true,
        v63_early_rules_ready: true,
        v63_score_signals_ready: true,
        v63_shadow_observation_ready: true,
        allowed_countries: [...csvSet(env.ALLOWED_COUNTRIES, "ES")],
        mobile_only: boolEnv(env.MOBILE_ONLY, true),
        humans_only: boolEnv(env.HUMANS_ONLY, true),
      });
    }

    if (url.pathname === "/_shadow/storage-test") {
      if (request.method !== "POST") {
        return Response.json({ error: "method_not_allowed" }, { status: 405 });
      }

      if (!adminAuthorized(request, env)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }

      const event = buildEvent({
        network,
        local: {
          risk: 0,
          spoofSignals: 0,
          strongHardwareSpoof: false,
          reasons: ["m1_shadow_storage_test"],
        },
        decision: "unknown",
        finalReasons: ["shadow_only", "no_v63_decision_yet"],
        telemetrySummary: {
          mode: "shadow",
          baseline: BASELINE,
          storage_test: true,
          raw_ip_stored: false,
          user_agent_stored: false,
        },
      });

      const [d1Result, r2Result] = await Promise.allSettled([
        insertEvent(env.DB, event),
        writeDatasetObject(env.DATASET, event),
      ]);

      const d1Written = d1Result.status === "fulfilled";
      const r2Written = r2Result.status === "fulfilled";

      return Response.json(
        {
          status: d1Written && r2Written ? "shadow_storage_ok" : "shadow_storage_partial",
          version: VERSION,
          event_id: event.event_id,
          d1_written: d1Written,
          r2_written: r2Written,
          raw_ip_stored: false,
          user_agent_stored: false,
        },
        { status: d1Written && r2Written ? 201 : 500 }
      );
    }

    if (url.pathname === "/_shadow/v63-preflight") {
      if (request.method !== "POST") {
        return Response.json({ error: "method_not_allowed" }, { status: 405 });
      }

      if (!adminAuthorized(request, env)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        body = {};
      }

      const syntheticNetwork = {
        ...network,
        country:
          typeof body.country === "string" ? body.country : network.country,
        asn: typeof body.asn === "string" ? body.asn : network.asn,
        bot: {
          ...(network.bot || {}),
          verifiedBot:
            typeof body.verifiedBot === "boolean"
              ? body.verifiedBot
              : !!network.bot?.verifiedBot,
        },
      };

      const testPath = typeof body.path === "string" ? body.path : "/";
      const testUa =
        typeof body.ua === "string"
          ? body.ua
          : request.headers.get("user-agent") || "";

      const result = evaluateV63EarlyRules({
        path: testPath,
        ua: testUa,
        network: syntheticNetwork,
        allowedCountries: csvSet(env.ALLOWED_COUNTRIES, "ES"),
        humansOnly: boolEnv(env.HUMANS_ONLY, true),
      });

      return Response.json({
        status: "v63_early_rules_shadow",
        version: VERSION,
        baseline: BASELINE,
        enforcing: false,
        input_summary: {
          path: testPath,
          country: syntheticNetwork.country,
          asn: syntheticNetwork.asn,
          verified_bot: !!syntheticNetwork.bot?.verifiedBot,
          ua_present: testUa.length > 0,
        },
        result,
      });
    }

    if (url.pathname === "/_shadow/v63-score") {
      if (request.method !== "POST") {
        return Response.json({ error: "method_not_allowed" }, { status: 405 });
      }

      if (!adminAuthorized(request, env)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        body = {};
      }

      const testUa =
        typeof body.ua === "string"
          ? body.ua
          : request.headers.get("user-agent") || "";

      const bodyBot = body.bot && typeof body.bot === "object" ? body.bot : {};
      const syntheticNetwork = {
        ...network,
        country:
          typeof body.country === "string" ? body.country : network.country,
        asn: typeof body.asn === "string" ? body.asn : network.asn,
        bot: {
          ...(network.bot || {}),
          ...bodyBot,
        },
      };

      const telemetry =
        body.telemetry && typeof body.telemetry === "object" ? body.telemetry : {};

      const result = scoreV63Signals({
        request,
        env,
        network: syntheticNetwork,
        ua: testUa,
        telemetry,
      });

      return Response.json({
        status: "v63_score_signals_shadow",
        version: VERSION,
        baseline: BASELINE,
        enforcing: false,
        input_summary: {
          country: syntheticNetwork.country,
          asn: syntheticNetwork.asn,
          ua_present: testUa.length > 0,
          telemetry_present: Object.keys(telemetry).length > 0,
        },
        result,
      });
    }

    if (url.pathname === "/_shadow/v63-observe") {
      if (request.method !== "POST") {
        return Response.json({ error: "method_not_allowed" }, { status: 405 });
      }

      if (!adminAuthorized(request, env)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }

      let body = {};
      try {
        body = await request.json();
      } catch {
        body = {};
      }

      const testUa =
        typeof body.ua === "string"
          ? body.ua
          : request.headers.get("user-agent") || "";
      const bodyBot = body.bot && typeof body.bot === "object" ? body.bot : {};
      const syntheticNetwork = {
        ...network,
        country:
          typeof body.country === "string" ? body.country : network.country,
        asn: typeof body.asn === "string" ? body.asn : network.asn,
        bot: {
          ...(network.bot || {}),
          ...bodyBot,
        },
      };
      const telemetry =
        body.telemetry && typeof body.telemetry === "object" ? body.telemetry : {};

      const score = scoreV63Signals({
        request,
        env,
        network: syntheticNetwork,
        ua: testUa,
        telemetry,
      });

      const event = buildEvent({
        network: syntheticNetwork,
        local: {
          risk: score.risk,
          spoofSignals: score.spoofSignals,
          strongHardwareSpoof: score.strongHardwareSpoof,
          reasons: score.reasons,
        },
        decision: "unknown",
        finalReasons: [
          "shadow_only",
          "v63_local_score_only",
          "synthetic_admin_test",
        ],
        telemetrySummary: {
          mode: "shadow",
          baseline: BASELINE,
          source: "admin_synthetic",
          dataset_eligible: false,
          raw_ip_stored: false,
          user_agent_stored: false,
          raw_telemetry_stored: false,
          critical: !!score.critical,
          ua_claim: uaClaimSummary(testUa),
          telemetry_sections: {
            navigator: !!telemetry.navigator,
            ua_data: !!telemetry.uaData,
            media: !!telemetry.media,
            webgl: !!telemetry.webgl,
            webgpu: !!telemetry.webgpu,
            automation: !!telemetry.automation,
          },
        },
      });

      const [d1Result, r2Result] = await Promise.allSettled([
        insertEvent(env.DB, event),
        writeDatasetObject(env.DATASET, event, { prefix: "tests" }),
      ]);

      const d1Written = d1Result.status === "fulfilled";
      const r2Written = r2Result.status === "fulfilled";

      return Response.json(
        {
          status:
            d1Written && r2Written
              ? "v63_shadow_observation_stored"
              : "v63_shadow_observation_partial",
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
          result: {
            risk: score.risk,
            spoofSignals: score.spoofSignals,
            strongHardwareSpoof: score.strongHardwareSpoof,
            critical: score.critical,
            reasons: score.reasons,
          },
        },
        { status: d1Written && r2Written ? 201 : 500 }
      );
    }

    return Response.json(
      {
        status: "v7_m1_shadow_only",
        version: VERSION,
        message: "V6.3 compatibility engine is not enforcing traffic yet.",
        ip_present: clientIp(request) !== "unknown",
      },
      { status: 503 }
    );
  },
};
