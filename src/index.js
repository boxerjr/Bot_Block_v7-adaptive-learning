import { csvSet, boolEnv } from "./engine/config.js";
import { clientIp, networkInfo } from "./engine/network.js";

const VERSION = "V7.0_BOOTSTRAP";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const network = networkInfo(request);

    if (url.pathname === "/_health") {
      return Response.json({
        status: "ok",
        version: VERSION,
        phase: "bootstrap",
        baseline: "V6.3_SILENT_AI",
        country: network.country,
        asn: network.asn,
        ai_bound: !!env.AI,
        d1_bound: !!env.DB,
        r2_bound: !!env.DATASET,
        allowed_countries: [...csvSet(env.ALLOWED_COUNTRIES, "ES")],
        mobile_only: boolEnv(env.MOBILE_ONLY, true),
        humans_only: boolEnv(env.HUMANS_ONLY, true),
      });
    }

    return Response.json(
      {
        status: "v7_bootstrap_only",
        version: VERSION,
        message: "V6.3 compatibility engine not yet enabled.",
        ip_present: clientIp(request) !== "unknown",
      },
      { status: 503 }
    );
  },
};
