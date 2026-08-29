import test from "node:test";
import assert from "node:assert/strict";

import { writeDatasetObject } from "../src/storage/dataset.js";

function fakeBucket() {
  const writes = [];
  return {
    writes,
    async put(key, value, options) {
      writes.push({ key, value, options });
    },
  };
}

const event = {
  event_id: "11111111-2222-3333-4444-555555555555",
  observed_at: "2026-08-29T12:00:00.000Z",
};

test("real dataset objects remain under events prefix", async () => {
  const bucket = fakeBucket();
  const key = await writeDatasetObject(bucket, event);

  assert.equal(
    key,
    "events/2026/08/29/11111111-2222-3333-4444-555555555555.json"
  );
  assert.equal(bucket.writes[0].key, key);
});

test("synthetic observations can be isolated under tests prefix", async () => {
  const bucket = fakeBucket();
  const key = await writeDatasetObject(bucket, event, { prefix: "tests" });

  assert.equal(
    key,
    "tests/2026/08/29/11111111-2222-3333-4444-555555555555.json"
  );
  assert.equal(bucket.writes[0].key, key);
});
