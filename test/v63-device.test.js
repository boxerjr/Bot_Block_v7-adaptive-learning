import test from "node:test";
import assert from "node:assert/strict";

import {
  headerDevice,
  evaluateV63MobileGate,
} from "../src/compat/v63/device.js";

const ANDROID_UA =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36";
const WINDOWS_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

test("V6.3 headerDevice classifies Android UA as mobile", () => {
  assert.equal(headerDevice({ ua: ANDROID_UA }).device, "mobile");
});

test("V6.3 headerDevice classifies Windows UA as desktop", () => {
  assert.equal(headerDevice({ ua: WINDOWS_UA }).device, "desktop");
});

test("Sec-CH-UA-Mobile ?1 forces mobile as in V6.3", () => {
  assert.equal(headerDevice({ ua: WINDOWS_UA, chMobile: "?1" }).device, "mobile");
});

test("Sec-CH-UA-Mobile ?0 classifies otherwise unknown UA as desktop", () => {
  assert.equal(headerDevice({ ua: "Mozilla/5.0", chMobile: "?0" }).device, "desktop");
});

test("MOBILE_ONLY blocks an obvious desktop", () => {
  const result = evaluateV63MobileGate({
    ua: WINDOWS_UA,
    chMobile: "?0",
    mobileOnly: true,
  });
  assert.equal(result.outcome, "block");
  assert.equal(result.reason, "desktop_not_allowed");
});

test("MOBILE_ONLY allows a mobile claimant past this gate", () => {
  const result = evaluateV63MobileGate({
    ua: ANDROID_UA,
    chMobile: "?1",
    mobileOnly: true,
  });
  assert.equal(result.outcome, "continue");
});

test("desktop continues when MOBILE_ONLY is disabled", () => {
  const result = evaluateV63MobileGate({
    ua: WINDOWS_UA,
    chMobile: "?0",
    mobileOnly: false,
  });
  assert.equal(result.outcome, "continue");
});
