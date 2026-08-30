import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  classifyLocalStaticUa,
  localStaticBotIntelEnabled,
  localStaticBotIntelStats,
} from "../src/adaptive/local-static-bot-intelligence.js";
import productionEntry from "../src/v7-global-honeypot-entry.js";

const entry = readFileSync(
  new URL("../src/v7-global-honeypot-entry.js", import.meta.url),
  "utf8"
);
const intelligence = readFileSync(
  new URL("../src/adaptive/local-static-bot-intelligence.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(
  new URL("../wrangler.jsonc", import.meta.url),
  "utf8"
);
const wranglerExample = readFileSync(
  new URL("../wrangler.example.jsonc", import.meta.url),
  "utf8"
);

test("precise scanners and automation clients hard-block locally", () => {
  for (const ua of [
    "sqlmap/1.8",
    "Mozilla/5.0 Acunetix-WebScanner/1.0",
    "masscan/1.3",
    "python-requests/2.32",
    "Mozilla/5.0 HeadlessChrome/151.0",
  ]) {
    const result = classifyLocalStaticUa(ua, { humansOnly: false });
    assert.equal(result.matched, true, ua);
    assert.equal(result.tier, "hard", ua);
    assert.equal(result.category, "scanner_or_automation", ua);
  }
});

test("self-declared crawlers block only under humans-only policy", () => {
  for (const ua of [
    "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "ClaudeBot/1.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "facebookexternalhit/1.1",
    "SemrushBot/7~bl",
  ]) {
    assert.equal(
      classifyLocalStaticUa(ua, { humansOnly: true }).matched,
      true,
      ua
    );
    assert.equal(
      classifyLocalStaticUa(ua, { humansOnly: false }).matched,
      false,
      ua
    );
  }
});

test("realistic mobile browsers and ambiguous upstream words are not matched", () => {
  for (const ua of [
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 SamsungBrowser/28.0 Chrome/130.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Bolt Buddy Disco Evil Curious Firefox/151.0",
  ]) {
    assert.equal(
      classifyLocalStaticUa(ua, { humansOnly: true }).matched,
      false,
      ua
    );
  }
});

test("local intelligence is enabled by default and has no runtime feed", () => {
  assert.equal(localStaticBotIntelEnabled({}), true);
  assert.equal(
    localStaticBotIntelEnabled({ LOCAL_STATIC_BOT_INTEL_ENABLED: "false" }),
    false
  );

  const stats = localStaticBotIntelStats();
  assert.ok(stats.scannerAutomationMarkers >= 40);
  assert.ok(stats.declaredBotMarkers >= 90);
  assert.ok(stats.totalMarkers >= 130);
  assert.equal(stats.mode, "vendored_local");
  assert.equal(stats.runtimeExternalDependency, false);
  assert.doesNotMatch(intelligence, /\bfetch\s*\(/);
  assert.match(wrangler, /"LOCAL_STATIC_BOT_INTEL_ENABLED"\s*:\s*"true"/);
  assert.match(
    wranglerExample,
    /"LOCAL_STATIC_BOT_INTEL_ENABLED"\s*:\s*"true"/
  );
});

test("production order blocks local static signatures before ASN, country and AI", () => {
  const exactIndex = entry.indexOf("const blocked = await globalExactIpBlock");
  const honeypotIndex = entry.indexOf("const match = classifyHoneypotPath");
  const localIndex = entry.indexOf("const localBotIntel = classifyLocalStaticUa");
  const communityIndex = entry.indexOf("const communityIntel = await classifyCommunityAsn");

  assert.ok(exactIndex >= 0);
  assert.ok(honeypotIndex > exactIndex);
  assert.ok(localIndex > honeypotIndex);
  assert.ok(communityIndex > localIndex);
  assert.match(entry, /BLOCK_BY_LOCAL_STATIC_UA/);
  assert.match(entry, /AI: skipped — local high-confidence signature/);
  assert.match(entry, /Training\/reputation update: false/);
  assert.match(entry, /v7_local_static_bot_intel_runtime_external_dependency/);
});

test("production wrapper enforces a local signature immediately", async () => {
  const request = new Request("https://v7.example/", {
    headers: {
      "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2)",
      "cf-connecting-ip": "203.0.113.44",
    },
  });
  const response = await productionEntry.fetch(
    request,
    {
      HUMANS_ONLY: "true",
      REDIRECT_ENFORCING: "true",
      BLOCK_URL: "https://blocked.example/",
    },
    {}
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://blocked.example/");
});
