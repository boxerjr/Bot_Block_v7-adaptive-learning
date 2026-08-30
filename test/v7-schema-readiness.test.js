import test from "node:test";
import assert from "node:assert/strict";
import {
  ensureReleaseAdditiveSchema,
  getReleaseSchemaHealth,
} from "../src/storage/schema-readiness.js";

const tables = [
  "installations",
  "events",
  "feedback",
  "asn_reputation",
  "fingerprint_reputation",
  "model_versions",
  "v63_fingerprint_shadow_state",
  "adaptive_feedback",
  "adaptive_asn_reputation",
  "adaptive_fingerprint_reputation",
  "adaptive_shadow_observations",
  "adaptive_live_capture_sessions",
  "asn_intelligence",
  "asn_intelligence_meta",
  "community_asn_intelligence",
  "community_intelligence_meta",
];

const triggers = [
  "trg_adaptive_feedback_clear_notes_insert",
  "trg_adaptive_feedback_clear_notes_update",
];

function fakeDb({ tableNames = tables, triggerNames = triggers } = {}) {
  return {
    prepare(sql) {
      return {
        bind(type) {
          return {
            async all() {
              if (!String(sql).includes("sqlite_master")) return { results: [] };
              const names = type === "table" ? tableNames : triggerNames;
              return { results: names.map((name) => ({ name })) };
            },
          };
        },
      };
    },
  };
}

test("release schema is ready only when migrations 0001 through 0007 are represented", async () => {
  const health = await getReleaseSchemaHealth(fakeDb());
  assert.equal(health.ready, true);
  assert.equal(health.reason, "ok");
  assert.deepEqual(health.missingMigrations, []);
  assert.equal(health.requiredMigrationCount, 7);
});

test("missing ASN/community tables expose the exact unapplied migrations", async () => {
  const health = await getReleaseSchemaHealth(fakeDb({
    tableNames: tables.filter((name) => ![
      "asn_intelligence",
      "asn_intelligence_meta",
      "community_asn_intelligence",
      "community_intelligence_meta",
    ].includes(name)),
  }));

  assert.equal(health.ready, false);
  assert.equal(health.reason, "schema_incomplete");
  assert.deepEqual(health.missingMigrations, [
    "0006_asn_intelligence.sql",
    "0007_community_intelligence.sql",
  ]);
});

test("runtime bootstrap creates only additive intelligence schema 0006 and 0007", async () => {
  let executed = "";
  const db = {
    async exec(sql) {
      executed = String(sql);
    },
  };

  const result = await ensureReleaseAdditiveSchema(db);
  assert.equal(result.ready, true);
  assert.deepEqual(result.bootstrappedMigrations, [
    "0006_asn_intelligence.sql",
    "0007_community_intelligence.sql",
  ]);

  assert.match(executed, /CREATE TABLE IF NOT EXISTS asn_intelligence/);
  assert.match(executed, /CREATE TABLE IF NOT EXISTS community_asn_intelligence/);
  assert.doesNotMatch(executed, /CREATE TABLE IF NOT EXISTS events/);
  assert.doesNotMatch(executed, /CREATE TABLE IF NOT EXISTS adaptive_live_capture_sessions/);
});

test("additive bootstrap reports D1 failure instead of claiming readiness", async () => {
  const db = {
    async exec() {
      throw new Error("D1 unavailable");
    },
  };

  const result = await ensureReleaseAdditiveSchema(db);
  assert.equal(result.ready, false);
  assert.equal(result.reason, "additive_schema_bootstrap_failed");
  assert.match(result.error, /D1 unavailable/);
});
