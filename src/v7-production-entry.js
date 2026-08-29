import policyWorker from "./m22-policy-enforcing-entry.js";
import {
  chooseFinalRedirect,
  redirectResponse,
  redirectState,
} from "./adaptive/redirect-policy.js";

function isMonitorPage(pathname) {
  return pathname === "/" || pathname === "" || pathname === "/check" || pathname === "/check/";
}

async function enrichHealth(request, env, ctx) {
  const response = await policyWorker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  const state = redirectState(env);
  return Response.json(
    {
      ...data,
      v7_release_mode: "production_redirect_ready",
      v7_redirect_requested: state.requested,
      v7_redirect_enabled: state.enabled,
      v7_origin_url_configured: state.originConfigured,
      v7_block_url_configured: state.blockConfigured,
      v7_redirect_country_block: "BLOCK_URL",
      v7_redirect_device_block: "BLOCK_URL",
      v7_redirect_manual_ip_block: "BLOCK_URL",
      v7_redirect_human: "ORIGIN_URL",
      v7_redirect_bot_spoof_review: "BLOCK_URL",
      v7_redirect_loop_guard: true,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function injectRedirectClient(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!response.ok || !contentType.includes("text/html")) return response;

  let html;
  try {
    html = await response.text();
  } catch {
    return response;
  }

  const marker = "const data = await response.json();";
  if (!html.includes(marker)) {
    return new Response(html, { status: response.status, headers: response.headers });
  }

  const injected = `${marker}\n      if (response.ok && data && data.redirect_enforcing === true && typeof data.redirect_url === \"string\" && data.redirect_url) {\n        const state = document.getElementById(\"state\");\n        if (state) state.textContent = \"Redirecting…\";\n        window.location.replace(data.redirect_url);\n        return;\n      }`;

  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("referrer-policy", "no-referrer");
  return new Response(html.replace(marker, injected), {
    status: response.status,
    headers,
  });
}

async function handleMonitorPage(request, env, ctx) {
  const response = await policyWorker.fetch(request, env, ctx);

  // Country, MOBILE_ONLY desktop, and exact-IP manual blocks currently return 404.
  // Once both redirect targets are configured, convert only that block response
  // into the configured BLOCK_URL redirect. Rate limits and other errors remain intact.
  if (response.status === 404) {
    const redirected = redirectResponse(request, env, "block");
    if (redirected) return redirected;
  }

  return injectRedirectClient(response);
}

async function handleFinalSubmit(request, env, ctx) {
  const response = await policyWorker.fetch(request, env, ctx);
  let data;
  try {
    data = await response.clone().json();
  } catch {
    return response;
  }

  if (data?.status !== "m22_public_monitor_observation") return response;

  const route = chooseFinalRedirect({
    env,
    requestUrl: request.url,
    monitorDetection: data.monitor_detection || {},
    v7Shadow: data.v7_shadow || null,
  });

  return Response.json(
    {
      ...data,
      redirect_enforcing: route.enabled,
      redirect_action: route.action,
      redirect_reason: route.reason,
      redirect_url: route.url,
      v7_redirect_enforcing: route.enabled,
      ai_bot_enforcing: route.enabled,
      enforcing: route.enabled,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/_health") {
      return enrichHealth(request, env, ctx);
    }

    if (request.method === "GET" && isMonitorPage(url.pathname)) {
      return handleMonitorPage(request, env, ctx);
    }

    if (url.pathname === "/_shadow/v7-monitor-submit") {
      return handleFinalSubmit(request, env, ctx);
    }

    return policyWorker.fetch(request, env, ctx);
  },
};
