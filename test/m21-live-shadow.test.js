import test from "node:test";
import assert from "node:assert/strict";

import {
  buildLiveLabelRecord,
  sanitizeLiveFeatureSummary,
} from "../src/adaptive/live-features.js";
import {
  issueLiveCaptureToken,
  verifyLiveCaptureToken,
} from "../src/adaptive/live-token.js";
import { verifyShadowBrowserToken } from "../src/compat/v63/shadow-token.js";

const SECRET = "m21-test-secret-not-production";

test("live token is valid only for M2.1 live capture", async () => {
  const { token, payload } = await issueLiveCaptureToken(SECRET, 90000);
  const verified = await verifyLiveCaptureToken(SECRET, token);

  assert.equal(verified?.sid, payload.sid);
  assert.equal(verified?.type, "m21_live_browser_probe");
  assert.equal(await verifyShadowBrowserToken(SECRET, token), null);
});

test("live feature summary is coarse and excludes raw browser strings", () => {
  const rawUa = "UNIQUE-RAW-UA-DO-NOT-STORE";
  const rawRenderer = "UNIQUE-RAW-GPU-RENDERER-DO-NOT-STORE";
  const rawTimezone = "UNIQUE/RAW_TIMEZONE";

  const summary = sanitizeLiveFeatureSummary({
    ua: `${rawUa} iPhone`,
    telemetry: {
      navigator: {
        platform: "iPhone",
        vendor: "Apple Computer, Inc.",
        hardwareConcurrency: 6,
        deviceMemory: 0,
        maxTouchPoints: 5,
        webdriver: false,
      },
      media: {
        pointerFine: false,
        pointerCoarse: true,
        anyHoverHover: false,
      },
      webgl: {
        vendor: "Apple Inc.",
        renderer: rawRenderer,
      },
      screen: {
        width: 393,
        height: 852,
        pixelRatio: 3,
      },
      timezone: { name: rawTimezone },
      automation: {},
      capabilities: {},
      interaction: {
        total: 2,
        trustedRatio: 1,
        touch: 1,
        mouse: 0,
        key: 0,
      },
    },
  });

  const encoded = JSON.stringify(summary);
  assert.equal(summary.device.platform_family, "ios");
  assert.equal(summary.device.screen_class, "phone");
  assert.equal(summary.gpu.vendor_family, "apple");
  assert.equal(encoded.includes(rawUa), false);
  assert.equal(encoded.includes(rawRenderer), false);
  assert.equal(encoded.includes(rawTimezone), false);
  assert.equal(encoded.includes("393"), false);
  assert.equal(encoded.includes("852"), false);
});

test("live label record contains truth label but no raw identifiers", () => {
  const label = buildLiveLabelRecord({
    eventId: "event-123",
    label: "human_confirmed",
    confidence: 100,
    createdAt: "2026-08-29T14:00:00.000Z",
  });

  assert.equal(label.scope, "live");
  assert.equal(label.training_eligible, true);
  assert.equal(label.raw_ip_stored, false);
  assert.equal(label.user_agent_stored, false);
  assert.equal(label.raw_telemetry_stored, false);
  assert.equal(label.label, "human_confirmed");
});
