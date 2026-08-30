import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  communityExportEnabled,
  communityHardBlockEnabled,
  communityUpstreamEnabled,
  communityUpstreamUrl,
} from "../src/adaptive/community-intelligence.js";

const community = readFileSync(
  new URL("../src/adaptive/community-intelligence.js", import.meta.url),
  "utf8"
);
const entry = readFileSync(
  new URL("../src/v7-global-honeypot-entry.js", import.meta.url),
  "utf8"
);
const workflow = readFileSync(
  new URL("../.github/workflows/community-intelligence-publish.yml", import.meta.url),
  "utf8"
);
const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");

test("community intelligence defaults are enabled and use canonical public feed", () => {
  assert.equal(communityExportEnabled({}), true);
  assert.equal(communityUpstreamEnabled({}), true);
  assert.equal(communityHardBlockEnabled({}), true);
  assert.match(
    communityUpstreamUrl({}),
    /boxerjr\/Bot_Block_v7-adaptive-learning\/community-feed\/community\/intelligence\.json/
  );
});

test("community HARD export accepts only V7 organization infrastructure", () => {
  assert.match(community, /source = 'org_auto_hard'/);
  assert.match(community, /source: "v7_org_infrastructure"/);
  assert.match(community, /String\(raw\?\.source \|\| ""\) !== "v7_org_infrastructure"/);
  assert.doesNotMatch(community, /WHERE source = 'spamhaus_asndrop'[^]*hardAsns/);
});

test("feedback consensus is RISK only and requires strong hostile evidence", () => {
  assert.match(community, /feedback_count >= 8/);
  assert.match(community, /hostile_weight >= 6/);
  assert.match(community, /human_weight <= 0\.25/);
  assert.match(community, /reputation_score <= 20/);
  assert.match(community, /tier: "risk"/);
  assert.match(community, /Feedback consensus is never promoted to global HARD/);
});

test("community export contains explicit privacy invariants and no fingerprint export query", () => {
  assert.match(community, /raw_ip: false/);
  assert.match(community, /user_agent: false/);
  assert.match(community, /fingerprint: false/);
  assert.match(community, /telemetry: false/);
  assert.match(community, /event_ids: false/);
  assert.doesNotMatch(community, /SELECT[^;]*fingerprint_id/i);
});

test("production checks exact IP and honeypot before community hard ASN", () => {
  const exact = entry.indexOf("const blocked = await globalExactIpBlock");
  const honey = entry.indexOf("const match = classifyHoneypotPath");
  const shared = entry.indexOf("const communityIntel = await classifyCommunityAsn");
  const downstream = entry.lastIndexOf("return worker.fetch(request, env, ctx)");
  assert.ok(exact >= 0);
  assert.ok(honey > exact);
  assert.ok(shared > honey);
  assert.ok(downstream > shared);
  assert.match(entry, /BLOCK_BY_COMMUNITY_ASN/);
  assert.match(entry, /\/_community\/intelligence\.json/);
});

test("scheduled production refreshes community feed while delegating existing cron jobs", () => {
  assert.match(entry, /refreshCommunityIntelligence\(env, Date\.now\(\)\)/);
  assert.match(entry, /worker\.scheduled\(controller, env, ctx\)/);
  assert.match(wrangler, /"COMMUNITY_INTEL_ENABLED": "true"/);
  assert.match(wrangler, /"COMMUNITY_INTEL_HARD_BLOCK_ENABLED": "true"/);
});

test("GitHub publisher writes only the community-feed branch after validation", () => {
  assert.match(workflow, /V7_COMMUNITY_FEED_URL/);
  assert.match(workflow, /ref: community-feed/);
  assert.match(workflow, /git push origin HEAD:community-feed/);
  assert.match(workflow, /Privacy invariant failed/);
  assert.match(workflow, /Unapproved HARD source/);
  assert.doesNotMatch(workflow, /git push origin HEAD:main/);
});
