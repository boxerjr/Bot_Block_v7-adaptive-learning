import test from "node:test";
import assert from "node:assert/strict";

import { scoreV63Signals } from "../src/compat/v63/score-signals.js";

function request(headers = {}) {
  return new Request("https://example.test/", { headers });
}

function score(overrides = {}) {
  return scoreV63Signals({
    request: request(),
    env: { HUMANS_ONLY: "true" },
    network: {
      country: "ES",
      asn: "AS14593",
      bot: null,
    },
    ua: "Mozilla/5.0",
    telemetry: {},
    ...overrides,
  });
}

test("safe ASN cannot produce negative final risk", () => {
  const result = score();
  assert.equal(result.risk, 0);
  assert.equal(result.critical, false);
  assert.equal(result.spoofSignals, 0);
  assert.equal(result.strongHardwareSpoof, false);
  assert.deepEqual(result.reasons, ["safe_access_asn"]);
});

test("risk ASN adds V6.3 risk_asn weight", () => {
  const result = score({
    network: { country: "ES", asn: "AS13335", bot: null },
  });
  assert.equal(result.risk, 30);
  assert.deepEqual(result.reasons, ["risk_asn"]);
});

test("hard ASN is critical and clamps to 100", () => {
  const result = score({
    network: { country: "ES", asn: "AS16509", bot: null },
  });
  assert.equal(result.risk, 100);
  assert.equal(result.critical, true);
  assert.ok(result.reasons.includes("hard_cloud_asn"));
});

test("Cloudflare bot score and failed JS detection preserve V6.3 weights", () => {
  const result = score({
    network: {
      country: "ES",
      asn: null,
      bot: { score: 5, verifiedBot: false, jsDetectionPassed: false },
    },
  });
  assert.equal(result.risk, 82);
  assert.deepEqual(result.reasons, [
    "cf_bot_score_1_5",
    "cf_js_detection_not_passed",
  ]);
});

test("high Cloudflare bot score plus passed JS detection reduces risk", () => {
  const result = score({
    network: {
      country: "ES",
      asn: "AS13335",
      bot: { score: 90, verifiedBot: false, jsDetectionPassed: true },
    },
  });
  assert.equal(result.risk, 17);
  assert.deepEqual(result.reasons, [
    "risk_asn",
    "cf_bot_score_high",
    "cf_js_detection_passed",
  ]);
});

test("navigator.webdriver is a critical automation signal", () => {
  const result = score({
    telemetry: { navigator: { webdriver: true } },
  });
  assert.equal(result.risk, 95);
  assert.equal(result.critical, true);
  assert.ok(result.reasons.includes("navigator_webdriver_true"));
});

test("claimed Android with correlated desktop hardware reaches strong spoof", () => {
  const ua =
    "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 Chrome/151.0 Mobile Safari/537.36";

  const result = score({
    request: request({
      "sec-ch-ua-platform": '"Windows"',
      "sec-ch-ua-mobile": "?0",
    }),
    ua,
    telemetry: {
      navigator: {
        maxTouchPoints: 0,
        platform: "Win32",
        hardwareConcurrency: 32,
      },
      uaData: {
        present: true,
        mobile: false,
        architecture: "x86",
      },
      media: {
        pointerFine: true,
        pointerCoarse: false,
        anyHoverHover: true,
      },
      webgl: {
        renderer: "NVIDIA GeForce RTX 4090",
        vendor: "NVIDIA",
      },
      webgpu: {
        description: "NVIDIA GeForce RTX 4090",
        vendor: "NVIDIA",
        architecture: "x86_64",
      },
    },
  });

  assert.equal(result.risk, 100);
  assert.equal(result.strongHardwareSpoof, true);
  assert.ok(result.spoofSignals >= 5);
  assert.ok(result.reasons.includes("desktop_gpu_plus_high_cpu_mobile_claim"));
  assert.ok(result.reasons.includes("dual_desktop_gpu_evidence"));
  assert.ok(result.reasons.includes("desktop_platform_plus_gpu_mobile_claim"));
  assert.ok(result.reasons.includes("multiple_spoof_contradictions"));
  assert.ok(result.reasons.includes("many_spoof_contradictions"));
});

test("iOS Safari contradiction signals are preserved", () => {
  const ua =
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1";

  const result = score({
    ua,
    telemetry: {
      navigator: {
        maxTouchPoints: 5,
        platform: "iPhone",
        vendor: "Google Inc.",
        deviceMemory: 8,
      },
      window: { chromePresent: true },
      uaData: { present: true, mobile: true },
      performance: { memoryPresent: true },
      capabilities: { usb: true },
      fonts: ["Segoe UI", "Calibri"],
    },
  });

  assert.equal(result.risk, 100);
  assert.ok(result.spoofSignals >= 5);
  assert.ok(result.reasons.includes("ios_safari_non_apple_vendor"));
  assert.ok(result.reasons.includes("ios_safari_window_chrome"));
  assert.ok(result.reasons.includes("ios_safari_user_agent_data"));
  assert.ok(result.reasons.includes("ios_safari_windows_fonts"));
});
