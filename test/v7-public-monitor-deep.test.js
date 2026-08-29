import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(
  new URL("../src/m22-deep-monitor-entry-v2.js", import.meta.url),
  "utf8"
);
const operational = readFileSync(
  new URL("../src/m22-operational-monitor-entry.js", import.meta.url),
  "utf8"
);
const policyWrapper = readFileSync(
  new URL("../src/m22-policy-enforcing-entry.js", import.meta.url),
  "utf8"
);
const deepHelper = readFileSync(
  new URL("../src/adaptive/monitor-deep-inspection.js", import.meta.url),
  "utf8"
);
const rateLimit = readFileSync(
  new URL("../src/adaptive/monitor-rate-limit.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

test("public monitor uses monitor-only deep inspection through policy gates", () => {
  assert.match(source, /runMonitorDeepInspection/);
  assert.match(source, /policy_baseline/);
  assert.match(source, /monitor_detection/);
  assert.match(source, /PolicyV6\.3:/);
  assert.match(source, /CountryGate:/);
  assert.match(source, /DeviceGate:/);
  assert.match(source, /MonitorDeepInspection:/);

  assert.match(deepHelper, /evaluateV63EarlyRules/);
  assert.match(deepHelper, /evaluateV63MobileGate/);
  assert.match(deepHelper, /scoreV63Signals/);
  assert.match(deepHelper, /fingerprintV63Reputation/);
  assert.match(deepHelper, /runV63AiPipeline/);
});

test("operational wrapper derives policy-neutral bot/spoof/human verdict", () => {
  assert.match(operational, /deriveMonitorVerdict/);
  assert.match(operational, /monitor_is_bot/);
  assert.match(operational, /monitor_is_spoof/);
  assert.match(operational, /monitor_final_decision/);
  assert.match(operational, /m22_policy_neutral_verdict_ready/);
  assert.match(operational, /TELEGRAM_TOKEN: undefined/);
  assert.match(operational, /buildTelegramDecisionMessage/);
});

test("root path is rewritten into the operational monitor page", () => {
  assert.match(operational, /function monitorPageRequest/);
  assert.match(operational, /url\.pathname = "\/check"/);
  assert.match(operational, /url\.pathname === "\/"/);
  assert.match(operational, /operationalCheck\(monitorPageRequest\(request\), env, ctx\)/);
  assert.match(operational, /m22_root_monitor_ready: true/);
});

test("country policy precedes mobile-only and monitor AI", () => {
  assert.match(policyWrapper, /countryAllowed/);
  assert.match(policyWrapper, /return operationalWorker\.fetch\(request, env, ctx\)/);
  assert.match(policyWrapper, /evaluateV63MobileGate/);
  assert.match(policyWrapper, /BLOCK_BY_DEVICE/);
  assert.match(policyWrapper, /desktop_not_allowed/);
  assert.match(policyWrapper, /status: 404/);
  assert.match(policyWrapper, /m22_policy_enforcement_order/);
});

test("public check has privacy-preserving anti-flood limiter", () => {
  assert.match(operational, /checkMonitorRateLimit/);
  assert.match(operational, /Too Many Monitor Requests/);
  assert.match(operational, /m22_rate_limit_ready/);
  assert.match(policyWrapper, /checkMonitorRateLimit/);
  assert.match(rateLimit, /HMAC/);
  assert.match(rateLimit, /networkBucket/);
  assert.match(rateLimit, /m22rl_/);
  assert.doesNotMatch(rateLimit, /INSERT[^;]*raw_ip/i);
});

test("deep monitor remains excluded from training while explicit policy gates enforce", () => {
  assert.match(source, /dataset_eligible: false/);
  assert.match(source, /training_eligible: false/);
  assert.match(source, /enforcing: false/);
  assert.match(source, /r2_written: false/);
  assert.match(source, /raw_ip_stored: false/);
  assert.match(source, /user_agent_stored: false/);
  assert.match(source, /raw_telemetry_stored: false/);
  assert.match(operational, /dataset_eligible: false/);
  assert.match(operational, /training_eligible: false/);
  assert.match(policyWrapper, /m22_ai_bot_enforcing: false/);
  assert.match(policyWrapper, /m22_mobile_only_desktop_enforcing/);
});

test("wrangler routes preview through policy-enforcing public monitor", () => {
  assert.match(wrangler, /"main": "src\/m22-policy-enforcing-entry\.js"/);
  assert.match(wrangler, /"ALLOWED_COUNTRIES": "ES"/);
  assert.match(wrangler, /"MOBILE_ONLY": "true"/);
});
