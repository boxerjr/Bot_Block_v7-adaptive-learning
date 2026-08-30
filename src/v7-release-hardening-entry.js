import worker from "./v7-global-honeypot-entry.js";
import { clientIp } from "./engine/network.js";
import { deriveManualIpKey } from "./adaptive/manual-ip-block.js";
import {
  issueMonitorToken,
  monitorTokenMatchesIpKey,
  verifyMonitorToken,
} from "./adaptive/monitor-token.js";
import { getReleaseSchemaHealth } from "./storage/schema-readiness.js";

const MAX_MONITOR_BODY_BYTES = 120_000;

function isMonitorPage(request) {
  if (request.method !== "GET") return false;
  const pathname = new URL(request.url).pathname;
  return pathname === "/" || pathname === "" || pathname === "/check" || pathname === "/check/";
}

function isMonitorSubmit(request) {
  return request.method === "POST" && new URL(request.url).pathname === "/_shadow/v7-monitor-submit";
}

function noStoreJson(body, status) {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

async function exactIpKey(request, env) {
  if (!env?.CHALLENGE_SECRET) return null;
  const ip = clientIp(request);
  if (!ip || ip === "unknown") return null;
  return deriveManualIpKey(env.CHALLENGE_SECRET, ip);
}

async function registerMonitorSession(db, payload) {
  if (!db || !payload?.sid) return false;
  try {
    await db
      .prepare(
        `INSERT INTO adaptive_live_capture_sessions
         (sid, issued_at_ms, expires_at_ms, consumed_at_ms)
         VALUES (?, ?, ?, NULL)`
      )
      .bind(payload.sid, Number(payload.iat), Number(payload.exp))
      .run();
    return true;
  } catch {
    return false;
  }
}

async function injectBoundMonitorToken(request, response, env) {
  if (!response.ok) return response;
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("text/html")) return response;
  if (!env?.DB || !env?.CHALLENGE_SECRET) {
    return noStoreJson({ error: "monitor_binding_infrastructure_unavailable" }, 503);
  }

  const ipKey = await exactIpKey(request, env);
  if (!ipKey) {
    return noStoreJson({ error: "trusted_client_ip_unavailable" }, 503);
  }

  let html;
  try {
    html = await response.text();
  } catch {
    return noStoreJson({ error: "monitor_page_read_failed" }, 503);
  }

  const marker = /const TOKEN = [^;]+;/;
  if (!marker.test(html)) {
    // Never return an unbound monitor token if the lower-layer HTML changes.
    return noStoreJson({ error: "monitor_token_binding_injection_failed" }, 503);
  }

  let issued;
  try {
    issued = await issueMonitorToken(
      env.CHALLENGE_SECRET,
      Number(env.PROBE_TOKEN_TTL_MS || 90000),
      ipKey
    );
  } catch {
    return noStoreJson({ error: "monitor_token_binding_failed" }, 503);
  }

  if (!(await registerMonitorSession(env.DB, issued.payload))) {
    return noStoreJson({ error: "monitor_bound_session_write_failed" }, 503);
  }

  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("referrer-policy", "no-referrer");
  const hardenedHtml = html.replace(
    marker,
    `const TOKEN = ${JSON.stringify(issued.token)};`
  );
  return new Response(hardenedHtml, { status: response.status, headers });
}

async function parseMonitorSubmitClone(request) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(declared) && declared > MAX_MONITOR_BODY_BYTES) {
    return { response: noStoreJson({ error: "payload_too_large" }, 413) };
  }

  let text;
  try {
    text = await request.clone().text();
  } catch {
    return { response: noStoreJson({ error: "invalid_body" }, 400) };
  }

  if (new TextEncoder().encode(text).byteLength > MAX_MONITOR_BODY_BYTES) {
    return { response: noStoreJson({ error: "payload_too_large" }, 413) };
  }

  try {
    return { body: JSON.parse(text) };
  } catch {
    return { response: noStoreJson({ error: "invalid_json" }, 400) };
  }
}

async function verifyBoundMonitorSubmit(request, env) {
  if (!env?.DB || !env?.CHALLENGE_SECRET) {
    return noStoreJson({ error: "monitor_binding_infrastructure_unavailable" }, 503);
  }

  const parsed = await parseMonitorSubmitClone(request);
  if (parsed.response) return parsed.response;

  const payload = await verifyMonitorToken(env.CHALLENGE_SECRET, parsed.body?.token || "");
  if (!payload) {
    return noStoreJson({ error: "invalid_or_expired_monitor_token" }, 401);
  }

  const ipKey = await exactIpKey(request, env);
  if (!ipKey) {
    return noStoreJson({ error: "trusted_client_ip_unavailable" }, 401);
  }

  if (!(await monitorTokenMatchesIpKey(env.CHALLENGE_SECRET, payload, ipKey))) {
    return noStoreJson({ error: "monitor_token_ip_mismatch" }, 401);
  }

  return null;
}

async function hardeningHealth(request, env, ctx) {
  const response = await worker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const schema = await getReleaseSchemaHealth(env?.DB);
  return Response.json(
    {
      ...data,
      v7_release: "7.0.0",
      v7_release_hardening: true,
      v7_release_ready: schema.ready,
      v7_schema_ready: schema.ready,
      v7_schema_reason: schema.reason,
      v7_schema_missing_tables: schema.missingTables,
      v7_schema_missing_triggers: schema.missingTriggers,
      v7_schema_missing_migrations: schema.missingMigrations,
      v7_schema_required_migration_count: schema.requiredMigrationCount || 7,
      v7_monitor_token_exact_ip_bound: true,
      v7_monitor_token_transfer_rejected: true,
      v7_enforcement_ip_source: "cf-connecting-ip_only",
      v7_monitor_body_limit_bytes: MAX_MONITOR_BODY_BYTES,
      v7_monitor_body_limit_checks_actual_bytes: true,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const pathname = new URL(request.url).pathname;

    if (pathname === "/_health") {
      return hardeningHealth(request, env, ctx);
    }

    if (isMonitorSubmit(request)) {
      const rejected = await verifyBoundMonitorSubmit(request, env);
      if (rejected) return rejected;
      return worker.fetch(request, env, ctx);
    }

    const response = await worker.fetch(request, env, ctx);
    if (isMonitorPage(request)) {
      return injectBoundMonitorToken(request, response, env);
    }
    return response;
  },

  async scheduled(controller, env, ctx) {
    if (typeof worker.scheduled === "function") {
      return worker.scheduled(controller, env, ctx);
    }
  },
};
