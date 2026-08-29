# M2.2 production-branch deploy trigger

This file exists only to trigger the Cloudflare Git integration after selecting `m2-2-public-monitor` as the production branch for the test Worker.

Safety invariants remain unchanged:
- `enforcing=false`
- `dataset_eligible=false`
- `training_eligible=false`
- no merge to `main`
- production V6.3 remains untouched

Triggered: 2026-08-29.
