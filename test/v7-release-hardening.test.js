import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { clientIp } from "../src/engine/network.js";
import { deriveManualIpKey } from "../src/adaptive/manual-ip-block.js";
import {
  issueMonitorToken,
  monitorTokenMatchesIpKey,
  verifyMonitorToken,
} from "../src/adaptive/monitor-token.js";

const hardeningEntry = readFileSync(
  new URL("../src/v7-release-hardening-entry.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

function requestWith(headers = {}) {
  return new Request("https://v7.example/check", { headers });
}

test("enforcement client IP trusts CF-Connecting-IP only", () => {
  assert.equal(
    clientIp(requestWith({ "cf-connecting-ip": "203.0.113.10", "x-forwarded-for": "198.51.100.1" })),
    "203.0.113.10"
  );
  assert.equal(clientIp(requestWith({ "x-forwarded-for": "198.51.100.1" })), "unknown");
});

test("monitor token is cryptographically bound to the issuing exact-IP HMAC", async () => {
  const secret = "release-hardening-monitor-secret";
  const ip1 = await deriveManualIpKey(secret, "203.0.113.10");
  const ip2 = await deriveManualIpKey(secret, "203.0.113.11");
  const issued = await issueMonitorToken(secret, 90_000, ip1);
  const payload = await verifyMonitorToken(secret, issued.token);

  assert.ok(payload);
  assert.match(payload.ipb, /^[A-Za-z0-9_-]{32}$/);
  assert.equal(await monitorTokenMatchesIpKey(secret, payload, ip1), true);
  assert.equal(await monitorTokenMatchesIpKey(secret, payload, ip2), false);
});

test("legacy unbound lower-layer token cannot satisfy production IP binding", async () => {
  const secret = "release-hardening-monitor-secret";
  const ipKey = await deriveManualIpKey(secret, "198.51.100.30");
  const issued = await issueMonitorToken(secret, 90_000);
  const payload = await verifyMonitorToken(secret, issued.token);

  assert.ok(payload);
  assert.equal(payload.ipb, null);
  assert.equal(await monitorTokenMatchesIpKey(secret, payload, ipKey), false);
});

test("production entrypoint cannot bypass release hardening", () => {
  assert.match(wrangler, /"main"\s*:\s*"src\/v7-release-hardening-entry\.js"/);
  assert.match(hardeningEntry, /monitor_token_ip_mismatch/);
  assert.match(hardeningEntry, /trusted_client_ip_unavailable/);
  assert.match(hardeningEntry, /MAX_MONITOR_BODY_BYTES = 120_000/);
  assert.match(hardeningEntry, /getReleaseSchemaHealth/);
});
