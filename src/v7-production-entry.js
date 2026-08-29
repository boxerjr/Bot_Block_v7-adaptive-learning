import policyWorker from "./m22-policy-enforcing-entry.js";
import {
  chooseFinalRedirect,
  redirectResponse,
  redirectState,
} from "./adaptive/redirect-policy.js";

function isMonitorPage(pathname) {
  return pathname === "/" || pathname === "" || pathname === "/check" || pathname === "/check/";
}

function silentRedirectShell(html) {
  const silentHead = `<style id="v7-silent-redirect-style">html.v7-silent-redirect,html.v7-silent-redirect body{margin:0!important;min-height:100%;background:#fff!important;overflow:hidden!important}html.v7-silent-redirect body>*:not(script){display:none!important}</style><script>document.documentElement.classList.add("v7-silent-redirect");setTimeout(()=>document.documentElement.classList.remove("v7-silent-redirect"),4000);</script>`;
  return html
    .replace("<title>V7 Public Traffic Monitor</title>", "<title></title>")
    .replace("</head>", `${silentHead}</head>`);
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
      v7_redirect_fully_configured: state.fullyConfigured,
      v7_origin_url_configured: state.originConfigured,
      v7_block_url_configured: state.blockConfigured,
      v7_origin_redirect_enabled: state.originEnabled,
      v7_block_redirect_enabled: state.blockEnabled,
      v7_silent_probe_enabled: state.originEnabled && state.blockEnabled,
      v7_redirect_country_block: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_device_block: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_manual_ip_block: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_human: "ORIGIN_URL",
      v7_redirect_bot_spoof_review: "BLOCK_URL_OR_404_FALLBACK",
      v7_redirect_loop_guard: true,
    },
    { status: response.status, headers: { "cache-control": "no-store" } }
  );
}

async function injectRedirectClient(response, env) {
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

  const state = redirectState(env);
  const silentReady = state.originEnabled && state.blockEnabled;
  if (silentReady) html = silentRedirectShell(html);

  const injected = `${marker}\n      if (response.ok && data && data.redirect_enforcing === true && typeof data.redirect_url === \"string\" && data.redirect_url) {\n        window.location.replace(data.redirect_url);\n        return;\n      }\n      document.documentElement.classList.remove(\"v7-silent-redirect\");`;

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

  // Known policy/manual blocks return 404 in the lower layer. In production:
  // - valid BLOCK_URL + REDIRECT_ENFORCING=true => 302 to BLOCK_URL
  // - missing/invalid BLOCK_URL => preserve the 404 fallback
  // Rate limits and non-404 errors remain untouched.
  if (response.status === 404) {
    const redirected = redirectResponse(request, env, "block");
    if (redirected) return redirected;
  }

  return injectRedirectClient(response, env);
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
      ai_bot_enforcing: route.enabled && route.action === "block",
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
