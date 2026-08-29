import test from "node:test";
import assert from "node:assert/strict";
import { runV63FullShadowDecision } from "../src/compat/v63/full-shadow.js";

function request(headers = {}) {
  return new Request("https://example.test/", { headers });
}

const desktopUa =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36";

const mobileUa =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/128.0.0.0 Mobile Safari/537.36";

test("country gate runs before desktop gate", async () => {
  const result = await runV63FullShadowDecision({
    request: request({ "sec-ch-ua-mobile": "?0" }),
    env: { ALLOWED_COUNTRIES: "ES", MOBILE_ONLY: "true", HUMANS_ONLY: "true" },
    network: { country: "RO", asn: "AS14593", bot: {} },
    ip: "203.0.113.10",
    ua: desktopUa,
    telemetry: {},
  });

  assert.equal(result.finalDecision, "block");
  assert.equal(result.decisionStage, "country");
  assert.equal(result.early.reason, "blocked_country");
  assert.equal(result.deviceGate, null);
  assert.equal(result.fingerprint.stored, false);
  assert.equal(result.ai.runAi, false);
});

test("desktop gate runs after early rules for allowed country", async () => {
  const result = await runV63FullShadowDecision({
    request: request({ "sec-ch-ua-mobile": "?0" }),
    env: { ALLOWED_COUNTRIES: "ES", MOBILE_ONLY: "true", HUMANS_ONLY: "true" },
    network: { country: "ES", asn: "AS14593", bot: {} },
    ip: "203.0.113.10",
    ua: desktopUa,
    telemetry: {},
  });

  assert.equal(result.finalDecision, "block");
  assert.equal(result.decisionStage, "obvious_desktop");
  assert.equal(result.early.outcome, "continue");
  assert.equal(result.deviceGate.reason, "desktop_not_allowed");
  assert.equal(result.fingerprint.stored, false);
  assert.equal(result.ai.runAi, false);
});

test("allowed mobile can reach post-AI allow path when AI is unavailable and fail-open", async () => {
  const result = await runV63FullShadowDecision({
    request: request({ "sec-ch-ua-mobile": "?1" }),
    env: {
      ALLOWED_COUNTRIES: "ES",
      MOBILE_ONLY: "true",
      HUMANS_ONLY: "true",
      AI_ENABLED: "true",
      AI_FAIL_CLOSED: "false",
    },
    network: { country: "ES", asn: "AS14593", bot: {} },
    ip: "203.0.113.10",
    ua: mobileUa,
    telemetry: {
      navigator: {
        userAgent: mobileUa,
        platform: "Linux armv8l",
        maxTouchPoints: 5,
        hardwareConcurrency: 8,
      },
      uaData: { present: true, mobile: true, architecture: "arm" },
      media: { pointerFine: false, pointerCoarse: true, anyHoverHover: false },
      webgl: { vendor: "Qualcomm", renderer: "Adreno 750" },
    },
  });

  assert.equal(result.early.outcome, "continue");
  assert.equal(result.deviceGate.outcome, "continue");
  assert.equal(result.finalDecision, "allow");
  assert.equal(result.decisionStage, "post_ai");
  assert.deepEqual(result.finalReasons, ["v63_allow"]);
});
