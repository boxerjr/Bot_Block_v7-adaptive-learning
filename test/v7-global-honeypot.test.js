import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  classifyHoneypotPath,
  honeypotRuleStats,
} from "../src/adaptive/honeypot-intelligence.js";

const entry = readFileSync(
  new URL("../src/v7-global-honeypot-entry.js", import.meta.url),
  "utf8"
);
const releaseEntry = readFileSync(
  new URL("../src/v7-release-hardening-entry.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);

test("baseline and extended secret paths are deterministic honeypots", () => {
  for (const path of [
    "/.env",
    "/.env.production",
    "/%2eenv.local",
    "/.git/config",
    "/.ssh/id_rsa",
    "/wp-admin",
    "/wp-admin/plugins.php",
    "/phpmyadmin",
    "/backup.zip",
    "/site.zip",
    "/secrets",
    "/.aws/credentials",
    "/server-status",
    "/manager/html",
    "/actuator/env",
    "/swagger-ui.html",
    "/appsettings.json",
    "/docker-compose.yml",
    "/.npmrc",
    "/_debugbar/open",
    "/backup-2026.sql",
    "/credentials.prod.pem",
  ]) {
    const result = classifyHoneypotPath(path);
    assert.equal(result.matched, true, path);
  }
});

test("normal public and V7 operational paths are not honeypots", () => {
  for (const path of [
    "/",
    "/check",
    "/favicon.ico",
    "/robots.txt",
    "/assets/app.js",
    "/downloads/manual.pdf",
    "/photos/backup.jpg",
    "/contact",
    "/_health",
    "/_telegram/webhook",
    "/_shadow/v7-monitor-submit",
  ]) {
    const result = classifyHoneypotPath(path);
    assert.equal(result.matched, false, path);
  }
});

test("path normalization defeats common case and encoding evasion", () => {
  assert.equal(classifyHoneypotPath("/.ENV.BAK").matched, true);
  assert.equal(classifyHoneypotPath("/%2Egit/config").matched, true);
  assert.equal(classifyHoneypotPath("\\.env").matched, true);
  assert.equal(classifyHoneypotPath("//wp-admin//setup-config.php").matched, true);
});

test("global honeypot wrapper blocks exact IP before downstream policy and preserves internal routes", () => {
  const exactIndex = entry.indexOf("const blocked = await globalExactIpBlock");
  const honeyIndex = entry.indexOf("const match = classifyHoneypotPath");
  const downstreamIndex = entry.lastIndexOf("return worker.fetch(request, env, ctx)");

  assert.ok(exactIndex >= 0);
  assert.ok(honeyIndex > exactIndex);
  assert.ok(downstreamIndex > honeyIndex);
  assert.match(entry, /setManualIpBlocked\(env\.DB, ipKey, null\)/);
  assert.match(entry, /BLOCK_BY_HONEYPOT/);
  assert.match(entry, /AI: skipped — hostile request target is deterministic/);
  assert.match(entry, /pathname\.startsWith\("\/_telegram\/"\)/);
  assert.match(entry, /pathname\.startsWith\("\/_shadow\/"\)/);
});

test("hosting or VPN honeypot hit can still promote ASN hard, consumer ISP does not get path-based promotion", () => {
  assert.match(entry, /\["hosting_cloud", "vpn_proxy"\]\.includes\(orgIntel\.class\)/);
  assert.match(entry, /promoteAsnToHardFromOrganization/);
  assert.match(entry, /consumer\/mobile ASN is not poisoned by one path probe/);
});

test("production release entry preserves global honeypot and cron wrapper", () => {
  assert.match(wrangler, /"main"\s*:\s*"src\/v7-release-hardening-entry\.js"/);
  assert.match(releaseEntry, /import worker from "\.\/v7-global-honeypot-entry\.js"/);
  assert.match(releaseEntry, /worker\.scheduled\(controller, env, ctx\)/);
  assert.match(wrangler, /"HONEYPOT_ENFORCING"\s*:\s*"true"/);
  assert.match(entry, /worker\.scheduled/);
});

test("extended honeypot layer substantially expands the immutable V6.3 baseline", () => {
  const stats = honeypotRuleStats();
  assert.ok(stats.baseline >= 40);
  assert.ok(stats.extendedExact >= 50);
  assert.ok(stats.extendedPrefix >= 15);
  assert.ok(stats.totalRuleEntries >= 100);
});
