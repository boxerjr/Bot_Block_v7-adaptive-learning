import test from "node:test";
import assert from "node:assert/strict";
import {
  hostileLearningFixture,
  SYNTHETIC_LEARNING_ASN,
} from "../src/adaptive/learning-fixture.js";

test("synthetic hostile learning fixture is isolated from live reputation", () => {
  const fixture = hostileLearningFixture();

  assert.equal(fixture.scope, "test");
  assert.equal(fixture.datasetEligible, false);
  assert.equal(fixture.synthetic, true);
  assert.equal(fixture.network.asn, SYNTHETIC_LEARNING_ASN);
  assert.equal(SYNTHETIC_LEARNING_ASN, "AS64512");
  assert.equal(fixture.v63Decision, "allow");
  assert.equal(fixture.v63DecisionStage, "post_ai");
  assert.equal(fixture.baseRisk, 45);
});
