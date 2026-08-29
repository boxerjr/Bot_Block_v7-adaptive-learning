import test from "node:test";
import assert from "node:assert/strict";

import {
  issueShadowBrowserToken,
  verifyShadowBrowserToken,
} from "../src/compat/v63/shadow-token.js";

test("shadow browser token verifies and carries the expected type", async () => {
  const token = await issueShadowBrowserToken("test-secret-value", 60000);
  const payload = await verifyShadowBrowserToken("test-secret-value", token);

  assert.ok(payload);
  assert.equal(payload.type, "m1_browser_probe");
  assert.ok(payload.sid);
  assert.ok(payload.exp > Date.now());
});

test("tampered shadow browser token is rejected", async () => {
  const token = await issueShadowBrowserToken("test-secret-value", 60000);
  const [body, signature] = token.split(".");
  const first = signature.at(0);
  const replacement = first === "A" ? "B" : "A";
  const tampered = `${body}.${replacement}${signature.slice(1)}`;

  const payload = await verifyShadowBrowserToken("test-secret-value", tampered);
  assert.equal(payload, null);
});

test("wrong secret rejects shadow browser token", async () => {
  const token = await issueShadowBrowserToken("test-secret-value", 60000);
  const payload = await verifyShadowBrowserToken("different-secret", token);
  assert.equal(payload, null);
});
