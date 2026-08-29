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

test("redirect engine is fail-safe until both HTTPS targets exist", () => {
  assert.equal(redirectState({ REDIRECT_ENFORCING: "true" }).enabled, false);
  assert.equal(
    redirectState({
      REDIRECT_ENFORCING: "true",
      ORIGIN_URL: "https://DESTINATIA-TA.com/",
      BLOCK_URL: "https://blocked.example.net/",
    }).enabled,
    false
  );
  assert.equal(
    redirectState({
      REDIRECT_ENFORCING: "true",
      ORIGIN_URL: "http://origin.example.net/",
      BLOCK_URL: "https://blocked.example.net/",
    }).enabled,
    false
  );
});

test("confirmed human traffic goes to ORIGIN_URL", () => {
  const route = chooseFinalRedirect({
    env,
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
  assert.match(wrangler, /"main": "src\/v7-production-entry\.js"/);
  assert.match(wrangler, /"REDIRECT_ENFORCING": "true"/);
  assert.doesNotMatch(wrangler, /"ORIGIN_URL"/);
  assert.doesNotMatch(wrangler, /"BLOCK_URL"/);
});
