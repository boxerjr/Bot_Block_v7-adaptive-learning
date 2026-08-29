# V7.0 Production Activation

Activation trigger for the production branch after Cloudflare production configuration was completed.

Runtime expectations:

- production branch: `main`
- `REDIRECT_ENFORCING=true`
- `ORIGIN_URL` supplied as a Cloudflare Secret
- `BLOCK_URL` supplied as a Cloudflare Secret
- country policy remains first
- `MOBILE_ONLY` device policy remains second
- exact-IP manual block remains available from Telegram
- allowed browser traffic continues through fingerprint/local/AI/V7 analysis
- human allow redirects to `ORIGIN_URL`
- country/device/manual-IP/bot/spoof/review/V7 review-or-block redirect to `BLOCK_URL`
- public observations remain `dataset_eligible=false` and `training_eligible=false`
- raw IP, raw User-Agent, and raw full telemetry remain unpersisted

This file intentionally contains no redirect destinations or secret values.
