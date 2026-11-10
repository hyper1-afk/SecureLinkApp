# DigitalOcean V2 staging template

`app-spec.staging.yaml` describes a separate App Platform application sourced
from `securelink-v2`. Pushes do not deploy automatically. Each manual deployment
runs exactly one `alembic upgrade head` pre-deploy job before the API is shifted
to the new release. The API has separate readiness and liveness checks. The
transactional email worker runs as a private worker component.

This is a template, not a deployment command. It creates no cloud resources and
does not reference the existing production app, database, domain, or secrets.
Before creating a staging app:

1. In DigitalOcean, select a staging-only hostname and dedicated PostgreSQL and
   Valkey resources. Attach them to a staging-only VPC and restrict their
   trusted sources to the staging API, email worker, migration job, and
   separately firewalled domain-monitor host.
2. Add the API, email worker, and migration job's required values as encrypted
   App Platform environment variables before the first deployment:
   `DATABASE_URL`, `REDIS_URL`, `APP_SECRET_KEY`,
   `EMAIL_OUTBOX_ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY`, `SMTP_HOST`,
   `SMTP_PORT`, `SMTP_FROM_EMAIL`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
   `DOMAIN_DNS_RESOLVERS`, and `EXTENSION_REDIRECT_URIS`. Add
   `TRUSTED_PROXY_CIDRS` only after confirming the real ingress peer ranges.
   Use a staging SMTP sender and destination.
3. Build `DATABASE_URL` with `sslmode=verify-full` and a trusted root
   certificate. Build `REDIS_URL` with `rediss://` plus certificate and
   hostname verification. The V2 API refuses weaker database/cache TLS
   settings and invalid staging secrets.
4. Configure the same approved numeric DNS resolver addresses in
   `DOMAIN_DNS_RESOLVERS` and the domain-monitor host firewall. Do not run the
   domain-monitor worker in App Platform: it needs enforceable DNS-only and
   database-only egress. The existing runbook describes that separate host and
   its firewall verification.
5. Add the exact OAuth callback for the unpacked staging extension to
   `EXTENSION_REDIRECT_URIS`. Keep the published extension callback and local
   preview callback separate from the staging package's actual ID.
6. Review the final spec and pricing in the DigitalOcean panel, validate the
   selected region/VPC and database binding, and keep first deployment manual.
   Do not point this app at production data, secrets, or DNS.

Do not store real secret values or encrypted DigitalOcean secret payloads in
this file. The app spec deliberately omits them so they can be entered and
encrypted in the DigitalOcean control panel. See [the staging runbook](../../docs/STAGING-RUNBOOK.md)
for TLS, firewall, restore, rollback, recovery, and operational checks.
