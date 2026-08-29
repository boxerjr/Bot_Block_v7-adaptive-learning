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
const deepHelper = readFileSync(
  new URL("../src/adaptive/monitor-deep-inspection.js", import.meta.url),
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

test("deep monitor remains non-enforcing and excluded from training", () => {
  assert.match(source, /dataset_eligible: false/);
  assert.match(source, /training_eligible: false/);
  assert.match(source, /enforcing: false/);
  assert.match(source, /r2_written: false/);
  assert.match(source, /raw_ip_stored: false/);
  assert.match(source, /user_agent_stored: false/);
  assert.match(source, /raw_telemetry_stored: false/);
  assert.match(operational, /enforcing: false/);
  assert.match(operational, /dataset_eligible: false/);
  assert.match(operational, /training_eligible: false/);
});

test("wrangler routes preview through operational public monitor", () => {
  assert.match(wrangler, /"main": "src\/m22-operational-monitor-entry\.js"/);
  assert.match(wrangler, /"ALLOWED_COUNTRIES": "ES"/);
  assert.match(wrangler, /"MOBILE_ONLY": "true"/);
});
