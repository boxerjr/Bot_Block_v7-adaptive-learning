import test from "node:test";
import assert from "node:assert/strict";
import { runMonitorDeepInspection } from "../src/adaptive/monitor-deep-inspection.js";

function desktopRequest() {
  return new Request("https://example.test/check", {
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36",
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
    },
  });
}

const telemetry = {
  navigator: {
    platform: "Win32",
    vendor: "Google Inc.",
    hardwareConcurrency: 8,
    deviceMemory: 8,
    maxTouchPoints: 0,
    webdriver: false,
  },
  screen: { width: 1920, height: 1080, pixelRatio: 1 },
  webgl: { renderer: "ANGLE (NVIDIA GeForce)" },
  media: { pointerFine: true, pointerCoarse: false, anyHoverHover: true },
};

test("monitor deep inspection continues after country policy block", async () => {
  const result = await runMonitorDeepInspection({
    request: desktopRequest(),
    env: {
      ALLOWED_COUNTRIES: "ES",
      MOBILE_ONLY: "true",
      HUMANS_ONLY: "true",
      AI_ENABLED: "false",
      LOCAL_HARD_BLOCK_THRESHOLD: "100",
    },
    network: { country: "RO", asn: "AS64500", org: "Test Network" },
    ip: "198.51.100.10",
    ua: desktopRequest().headers.get("user-agent"),
    telemetry,
  });

  assert.equal(result.policyBaseline.finalDecision, "block");
  assert.equal(result.policyBaseline.decisionStage, "country");
  assert.equal(result.monitorDeepInspection, true);
  assert.equal(result.deviceGate.outcome, "block");
  assert.equal(result.deviceGate.stage, "obvious_desktop");
  assert.notEqual(result.decisionStage, "country");
  assert.notEqual(result.decisionStage, "obvious_desktop");
  assert.equal(result.ai.runAi, false);
});

test("monitor deep inspection continues after desktop-only policy block in allowed country", async () => {
  const request = desktopRequest();
  const result = await runMonitorDeepInspection({
    request,
    env: {
      ALLOWED_COUNTRIES: "ES",
      MOBILE_ONLY: "true",
      HUMANS_ONLY: "true",
      AI_ENABLED: "false",
      LOCAL_HARD_BLOCK_THRESHOLD: "100",
    },
    network: { country: "ES", asn: "AS64500", org: "Test Network" },
    ip: "198.51.100.11",
    ua: request.headers.get("user-agent"),
    telemetry,
  });

  assert.equal(result.early.outcome, "continue");
  assert.equal(result.policyBaseline.finalDecision, "block");
  assert.equal(result.policyBaseline.decisionStage, "obvious_desktop");
  assert.equal(result.monitorDeepInspection, true);
  assert.notEqual(result.decisionStage, "obvious_desktop");
});
