import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  chooseFinalRedirect,
  redirectResponse,
  redirectState,
} from "../src/adaptive/redirect-policy.js";

const production = readFileSync(
  new URL("../src/v7-production-entry.js", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

const env = {
  REDIRECT_ENFORCING: "true",
  ORIGIN_URL: "https://origin.example.net/",
  BLOCK_URL: "https://blocked.example.net/",
};

test("redirect readiness is per target", () => {
  const none = redirectState({ REDIRECT_ENFORCING: "true" });
  assert.equal(none.enabled, false);
  assert.equal(none.originEnabled, false);
  assert.equal(none.blockEnabled, false);

  const blockOnly = redirectState({
    REDIRECT_ENFORCING: "true",
    BLOCK_URL: "https://blocked.example.net/",
  });
  assert.equal(blockOnly.enabled, true);
  assert.equal(blockOnly.blockEnabled, true);
  assert.equal(blockOnly.originEnabled, false);
  assert.equal(blockOnly.fullyConfigured, false);

  const invalidOriginWithBlock = redirectState({
    REDIRECT_ENFORCING: "true",
    ORIGIN_URL: "http://origin.example.net/",
    BLOCK_URL: "https://blocked.example.net/",
  });
  assert.equal(invalidOriginWithBlock.blockEnabled, true);
  assert.equal(invalidOriginWithBlock.originEnabled, false);
});

test("blocked traffic redirects whenever BLOCK_URL is configured even without ORIGIN_URL", () => {
  const blockOnlyEnv = {
    REDIRECT_ENFORCING: "true",
    BLOCK_URL: "https://blocked.example.net/",
  };

  const response = redirectResponse(
    new Request("https://monitor.example.net/"),
    blockOnlyEnv,
    "block"
  );
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://blocked.example.net/");

  const route = chooseFinalRedirect({
    env: blockOnlyEnv,
    requestUrl: "https://monitor.example.net/_shadow/v7-monitor-submit",
    monitorDetection: { final_decision: "block", classification: "spoofed_device" },
    v7Shadow: { ready: true, decision: "block" },
  });
  assert.equal(route.enabled, true);
  assert.equal(route.action, "block");
  assert.equal(route.url, "https://blocked.example.net/");
});

test("blocked traffic keeps 404 fallback when BLOCK_URL is missing or invalid", () => {
  const missing = redirectResponse(
    new Request("https://monitor.example.net/"),
    { REDIRECT_ENFORCING: "true" },
    "block"
  );
  assert.equal(missing, null);

  const invalid = redirectResponse(
    new Request("https://monitor.example.net/"),
    {
      REDIRECT_ENFORCING: "true",
      BLOCK_URL: "https://SITE-REAL-PE-CARE-IL-CONTROLEZI.com/",
    },
    "block"
  );
  assert.equal(invalid, null);

  const route = chooseFinalRedirect({
    env: { REDIRECT_ENFORCING: "true" },
    requestUrl: "https://monitor.example.net/_shadow/v7-monitor-submit",
    monitorDetection: { final_decision: "block", classification: "automation" },
    v7Shadow: { ready: true, decision: "block" },
  });
  assert.equal(route.enabled, false);
  assert.equal(route.action, "block");
  assert.equal(route.reason, "block_redirect_not_configured");
});

test("confirmed human traffic goes to ORIGIN_URL independently of BLOCK_URL", () => {
  const originOnlyEnv = {
    REDIRECT_ENFORCING: "true",
    ORIGIN_URL: "https://origin.example.net/",
  };
  const route = chooseFinalRedirect({
    env: originOnlyEnv,
    requestUrl: "https://monitor.example.net/_shadow/v7-monitor-submit",
    monitorDetection: { final_decision: "allow", classification: "human_mobile" },
    v7Shadow: { ready: true, decision: "allow" },
  });
  assert.equal(route.enabled, true);
  assert.equal(route.action, "origin");
  assert.equal(route.url, "https://origin.example.net/");
});

test("bot, spoof, review, and V7 review/block go to BLOCK_URL", () => {
  for (const classification of ["automation", "crawler", "spoofed_device"]) {
    const route = chooseFinalRedirect({
      env,
      requestUrl: "https://monitor.example.net/_shadow/v7-monitor-submit",
      monitorDetection: { final_decision: "block", classification },
      v7Shadow: { ready: true, decision: "block" },
    });
    assert.equal(route.action, "block");
    assert.equal(route.url, "https://blocked.example.net/");
  }

  const review = chooseFinalRedirect({
    env,
    requestUrl: "https://monitor.example.net/_shadow/v7-monitor-submit",
    monitorDetection: { final_decision: "review", classification: "unknown" },
    v7Shadow: { ready: true, decision: "review" },
  });
  assert.equal(review.action, "block");

  const adaptiveReview = chooseFinalRedirect({
    env,
    requestUrl: "https://monitor.example.net/_shadow/v7-monitor-submit",
    monitorDetection: { final_decision: "allow", classification: "human_mobile" },
    v7Shadow: { ready: true, decision: "review" },
  });
  assert.equal(adaptiveReview.action, "block");
});

test("server redirect has loop guard and no-store headers", () => {
  const blocked = redirectResponse(new Request("https://monitor.example.net/"), env, "block");
  assert.equal(blocked.status, 302);
  assert.equal(blocked.headers.get("location"), "https://blocked.example.net/");
  assert.equal(blocked.headers.get("cache-control"), "no-store");

  const loop = redirectResponse(
    new Request("https://blocked.example.net/"),
    env,
    "block"
  );
  assert.equal(loop, null);
});

test("production wrapper redirects after browser probe and wrangler exposes no target URLs", () => {
  assert.match(production, /window\.location\.replace\(data\.redirect_url\)/);
  assert.match(production, /chooseFinalRedirect/);
  assert.match(production, /response\.status === 404/);
  assert.match(production, /BLOCK_URL_OR_404_FALLBACK/);
  assert.match(wrangler, /"main": "src\/v7-production-entry\.js"/);
  assert.match(wrangler, /"REDIRECT_ENFORCING": "true"/);
  assert.doesNotMatch(wrangler, /"ORIGIN_URL"/);
  assert.doesNotMatch(wrangler, /"BLOCK_URL"/);
});
