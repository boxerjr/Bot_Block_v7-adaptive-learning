import { csvSet, boolEnv } from "./engine/config.js";
import { clientIp, networkInfo } from "./engine/network.js";
import { buildEvent } from "./adaptive/events.js";
import { insertEvent } from "./storage/d1.js";
import { writeDatasetObject } from "./storage/dataset.js";
import { evaluateV63EarlyRules } from "./compat/v63/preflight.js";

const VERSION = "V7.0_M1_SHADOW";
const BASELINE = "V6.3_SILENT_AI";

function adminAuthorized(request, env) {
  const direct = request.headers.get("x-admin-secret") || "";
  const auth = request.headers.get("authorization") || "";
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const supplied = direct || bearer;
  return !!env.ADMIN_SECRET && supplied === env.ADMIN_SECRET;
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
