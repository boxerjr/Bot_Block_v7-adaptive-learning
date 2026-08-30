const healthUrl = String(process.env.V7_PRODUCTION_HEALTH_URL || "").trim();
if (!healthUrl) {
  console.error("V7_PRODUCTION_HEALTH_URL is required");
  process.exit(2);
}

const attempts = Math.max(1, Math.min(12, Number(process.env.V7_SMOKE_ATTEMPTS || 9)));
const delayMs = Math.max(1000, Math.min(30000, Number(process.env.V7_SMOKE_DELAY_MS || 10000)));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function validateHealth(data) {
  const failures = [];

  if (data?.v7_release !== "7.0.0") failures.push(`v7_release=${JSON.stringify(data?.v7_release)}`);
  if (data?.v7_release_hardening !== true) failures.push(`v7_release_hardening=${JSON.stringify(data?.v7_release_hardening)}`);
  if (data?.v7_release_ready !== true) failures.push(`v7_release_ready=${JSON.stringify(data?.v7_release_ready)}`);
  if (data?.v7_schema_ready !== true) failures.push(`v7_schema_ready=${JSON.stringify(data?.v7_schema_ready)}`);

  const missingTables = Array.isArray(data?.v7_schema_missing_tables) ? data.v7_schema_missing_tables : null;
  const missingTriggers = Array.isArray(data?.v7_schema_missing_triggers) ? data.v7_schema_missing_triggers : null;
  const missingMigrations = Array.isArray(data?.v7_schema_missing_migrations) ? data.v7_schema_missing_migrations : null;

  if (!missingTables || missingTables.length) failures.push(`missing_tables=${JSON.stringify(missingTables)}`);
  if (!missingTriggers || missingTriggers.length) failures.push(`missing_triggers=${JSON.stringify(missingTriggers)}`);
  if (!missingMigrations || missingMigrations.length) failures.push(`missing_migrations=${JSON.stringify(missingMigrations)}`);

  if (data?.v7_monitor_token_exact_ip_bound !== true) failures.push(`token_ip_bound=${JSON.stringify(data?.v7_monitor_token_exact_ip_bound)}`);
  if (data?.v7_monitor_token_transfer_rejected !== true) failures.push(`token_transfer_rejected=${JSON.stringify(data?.v7_monitor_token_transfer_rejected)}`);
  if (data?.v7_enforcement_ip_source !== "cf-connecting-ip_only") failures.push(`ip_source=${JSON.stringify(data?.v7_enforcement_ip_source)}`);
  if (Number(data?.v7_monitor_body_limit_bytes) !== 120000) failures.push(`body_limit=${JSON.stringify(data?.v7_monitor_body_limit_bytes)}`);
  if (data?.v7_monitor_body_limit_checks_actual_bytes !== true) failures.push(`actual_body_limit=${JSON.stringify(data?.v7_monitor_body_limit_checks_actual_bytes)}`);

  if (data?.v7_local_static_bot_intel_enabled !== true) failures.push(`local_static_bot_intel_enabled=${JSON.stringify(data?.v7_local_static_bot_intel_enabled)}`);
  if (data?.v7_local_static_bot_intel_mode !== "vendored_local") failures.push(`local_static_bot_intel_mode=${JSON.stringify(data?.v7_local_static_bot_intel_mode)}`);
  if (data?.v7_local_static_bot_intel_runtime_external_dependency !== false) failures.push(`local_static_bot_intel_external_dependency=${JSON.stringify(data?.v7_local_static_bot_intel_runtime_external_dependency)}`);
  if (Number(data?.v7_local_static_bot_intel_total_markers) < 150) failures.push(`local_static_bot_intel_markers=${JSON.stringify(data?.v7_local_static_bot_intel_total_markers)}`);
  if (data?.v7_local_static_bot_intel_precedes_asn_country_ai !== true) failures.push(`local_static_bot_intel_order=${JSON.stringify(data?.v7_local_static_bot_intel_precedes_asn_country_ai)}`);
  if (data?.v7_local_static_bot_intel_raw_ua_stored !== false) failures.push(`local_static_bot_intel_raw_ua=${JSON.stringify(data?.v7_local_static_bot_intel_raw_ua_stored)}`);
  if (data?.v7_local_static_bot_intel_training_eligible !== false) failures.push(`local_static_bot_intel_training=${JSON.stringify(data?.v7_local_static_bot_intel_training_eligible)}`);

  return failures;
}

let lastError = null;
for (let attempt = 1; attempt <= attempts; attempt += 1) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const response = await fetch(healthUrl, {
      method: "GET",
      headers: {
        accept: "application/json",
        "user-agent": "V7-Production-Smoke/7.0.0",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    const text = await response.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`non_json_response status=${response.status} body=${text.slice(0, 300)}`);
    }

    if (!response.ok) {
      throw new Error(`health_http_${response.status}: ${JSON.stringify(data).slice(0, 600)}`);
    }

    const failures = validateHealth(data);
    if (!failures.length) {
      console.log(`V7 production smoke PASS on attempt ${attempt}`);
      console.log(JSON.stringify({
        v7_release: data.v7_release,
        v7_release_ready: data.v7_release_ready,
        v7_schema_ready: data.v7_schema_ready,
        v7_schema_missing_migrations: data.v7_schema_missing_migrations,
        v7_monitor_token_exact_ip_bound: data.v7_monitor_token_exact_ip_bound,
        v7_enforcement_ip_source: data.v7_enforcement_ip_source,
        v7_local_static_bot_intel_enabled: data.v7_local_static_bot_intel_enabled,
        v7_local_static_bot_intel_mode: data.v7_local_static_bot_intel_mode,
        v7_local_static_bot_intel_total_markers: data.v7_local_static_bot_intel_total_markers,
        v7_local_static_bot_intel_runtime_external_dependency: data.v7_local_static_bot_intel_runtime_external_dependency,
      }, null, 2));
      process.exit(0);
    }

    lastError = new Error(`health_not_ready: ${failures.join("; ")}`);
    console.error(`Attempt ${attempt}/${attempts}: ${lastError.message}`);
  } catch (error) {
    lastError = error;
    console.error(`Attempt ${attempt}/${attempts}: ${String(error?.message || error)}`);
  }

  if (attempt < attempts) await sleep(delayMs);
}

console.error(`V7 production smoke FAILED: ${String(lastError?.message || lastError || "unknown")}`);
process.exit(1);
