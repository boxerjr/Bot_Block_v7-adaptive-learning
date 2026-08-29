import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../src/m22-deep-monitor-entry.js", import.meta.url), "utf8");
const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

test("public monitor preserves country policy but continues shadow inspection", () => {
  assert.match(source, /policyDecision\.finalDecision === "block"/);
  assert.match(source, /policyDecision\.decisionStage === "country"/);
  assert.match(source, /monitorEnvAllowingCountry/);
  assert.match(source, /deep_inspection_after_country_policy_block/);
  assert.match(source, /PolicyV6\.3:/);
  assert.match(source, /MonitorDeepInspection:/);
});

test("deep monitor remains non-enforcing and excluded from training", () => {
  assert.match(source, /dataset_eligible: false/);
  assert.match(source, /training_eligible: false/);
  assert.match(source, /enforcing: false/);
  assert.match(source, /r2_written: false/);
  assert.match(source, /raw_ip_stored: false/);
  assert.match(source, /user_agent_stored: false/);
  assert.match(source, /raw_telemetry_stored: false/);
});

test("wrangler routes the preview through the deep monitor wrapper", () => {
  assert.match(wrangler, /"main": "src\/m22-deep-monitor-entry\.js"/);
  assert.match(wrangler, /"ALLOWED_COUNTRIES": "ES"/);
});
