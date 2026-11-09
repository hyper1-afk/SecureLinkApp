# DigitalOcean V2 staging runbook

This is a preparation runbook. It creates no DigitalOcean resources and contains no credentials. Keep the existing production app, domain routing, databases, and secrets separate.

## Resource layout

Create a distinct DigitalOcean App Platform app named `securelink-v2-staging` from branch `securelink-v2`, with a staging-only hostname. Place the app, Managed PostgreSQL, and Managed Valkey in the same region and private network where supported. Do not bind staging to the legacy production database or production mail account.

Use App Platform encrypted secret environment variables for `APP_SECRET_KEY`, `EMAIL_OUTBOX_ENCRYPTION_KEY`, `DATABASE_URL`, `REDIS_URL`, and SMTP credentials. Set `TRUSTED_PROXY_CIDRS` only to verified ingress proxy CIDRs; leave it empty until the real immediate peer ranges are confirmed. Never trust client-provided forwarding headers by default. Generate a unique Fernet key for each environment and protect it as a high-impact secret. Use staging-only values. Configure `APP_ENV=staging`, `APP_PUBLIC_URL=https://<staging-host>`, `SMTP_STARTTLS=true`, and a least-privilege database user. Never put secrets in this runbook, app spec, or GitHub commit.

## Deployment sequence

1. Provision isolated API and email-worker components, PostgreSQL, and Valkey resources. Run the worker as a separate long-running component from the same image and give it only the required environment secrets. Restrict database trusted sources to the staging app and authorized admin path; prefer same-region private networking.
2. Add SMTP provider credentials dedicated to staging. Configure a test sender and inbox. Do not deliver staging mail to real users.
3. Configure the app health check to `/health/ready` and a separate liveness check to `/health/live`.
4. Keep deployment manual while migrations and auth workflows are being exercised. Run `alembic upgrade head` as a single deployment step before shifting traffic; do not run concurrent migrations from every app replica.
5. Confirm the database is on the expected migration revision. Exercise registration, email verification, login, password reset, reset-token replay, role denial, cross-tenant denial, Redis throttling, and expired access tokens.
6. Verify logs omit email action tokens and passwords. Verify 429 behavior and 503 fail-closed behavior when Valkey is unavailable.
7. Restore a PostgreSQL backup into a separate staging cluster and document measured recovery time and data loss window. Managed PostgreSQL provides daily full backups and point-in-time recovery for the prior seven days; validate an actual restore before relying on it.
8. Record deploy commit, migration revision, health status, alert routing, rollback steps, and restore evidence before considering any production promotion.

## Operational gates

- Account-action messages use a transactional encrypted outbox and separate worker with leases/retries. Alert on oldest pending row, failed rows, and worker health. An SMTP timeout after server acceptance can create duplicate delivery; action links remain single-use.
- Alert on failed health checks, elevated 5xx/429 rates, database/Valkey unavailability, failed mail delivery, and migration failures.
- Limit SMTP and database credentials to the staging resources; rotate them after staging validation.
- Establish retention and access controls for staging logs and test accounts.
- Confirm the reverse proxy's actual peer ranges and forwarded chain in staging before populating `TRUSTED_PROXY_CIDRS`; verify spoofed forwarding headers cannot change the rate-limit key.
- Maintain an app image/commit rollback procedure and a compatible database migration downgrade or forward-fix plan.
- No production DNS cutover or production secret reuse is part of this runbook.
