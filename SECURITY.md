# Security Policy

## Reporting

Do not publish credentials, Cloudflare secrets, Telegram bot tokens, raw IP addresses, private telemetry, or private customer/user data in GitHub issues or pull requests.

For a suspected vulnerability, use a private reporting channel associated with the repository owner rather than a public issue.

## Secrets

Production values must be stored in Cloudflare Secrets or another approved secret store. In particular:

- `CHALLENGE_SECRET`
- `ADMIN_SECRET`
- `TELEGRAM_TOKEN`
- `TELEGRAM_CHAT_ID`
- `ORIGIN_URL`
- `BLOCK_URL`

The repository must contain only placeholders/examples for these values.

## Privacy invariants

Public monitor observations must not persist raw IP addresses, raw User-Agent strings, or raw full browser telemetry. Public observations are excluded from automatic training and truth labeling.

## Production changes

Changes to policy enforcement, redirect routing, adaptive thresholds, fingerprinting, or training eligibility should be covered by regression tests before deployment.
