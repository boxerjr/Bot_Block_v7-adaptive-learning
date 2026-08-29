# Operator feedback learning

V7 can learn from explicit Telegram operator BLOCK actions without treating its own AI decisions as truth.

- If an event was originally allowed by the V6.3-compatible pipeline and the operator explicitly presses `BLOCK IP`, V7 records `false_negative` feedback with confidence 100.
- Reputation is rebuilt for the event fingerprint and ASN using the existing adaptive reputation model.
- Public monitor observations remain outside the training dataset because their existing `dataset_eligible` value is false.
- Controlled M2.1 observations preserve their pre-existing dataset eligibility.
- A pre-existing feedback label is never overwritten.
- If event mapping is unavailable, Telegram falls back to exact-IP blocking without inventing a training label.
- Raw IP, raw UA, and raw telemetry are not added by this feedback path.
