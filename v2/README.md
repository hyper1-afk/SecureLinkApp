# SecureLink 2.0

SecureLink 2.0 is an evidence-first security operations platform developed separately from the legacy application at the repository root. Do not connect production customer data until the migration and security reviews are approved.

## Current API foundation

- Email verification is required before login. A same-origin account page supports registration, sign-in, verification, resend, and password recovery.
- Password reset links are single-use, expire, and are stored as token digests. Delivery uses a database outbox with encrypted payloads and a separate retrying worker.
- Password reset and logout increment a token version and invalidate existing access tokens.
- Login and account lifecycle endpoints use Redis-backed IP rate limits and return 503 if Redis protection is unavailable.
- Organization access is checked against current membership on every request. Owners/admins can list members; owner/admin role changes and member removals are audited, with last-owner protection and stricter admin limits.
- Audit events are append-only in PostgreSQL.
- Access tokens expire after 15 minutes.

## Development

1. Install Git, Docker Desktop (WSL2 backend), and Python 3.12.
2. From PowerShell: `cd v2`
3. Copy `.env.example` to `.env` and set unique `APP_SECRET_KEY` and `EMAIL_OUTBOX_ENCRYPTION_KEY` values, a database password, and an SMTP test account.
4. Set `APP_PUBLIC_URL` to the local API origin; it also serves the account pages and securely exchanges the one-time email links.
5. Configure `EMAIL_OUTBOX_ENCRYPTION_KEY` with a generated Fernet key, then start services: `docker compose up --build`
6. API docs: http://localhost:8000/docs; liveness: http://localhost:8000/health/live.

SMTP must use STARTTLS. In production, the public URL must use HTTPS. Never commit populated secrets or use production credentials in local development.

## Workspace

- `apps/api`: HTTP API and application composition
- `packages/security_core`: identity and tenant data models
- `migrations`: Alembic migrations
- `docs`: architecture, threat model, staging runbook and extension redesign
- `tests`: unit, PostgreSQL migration and API tests

## Production status

Not production-ready. The account page and email verification/reset pages are implemented; the product dashboard and security-scanning workflows are not. Membership invitations/ownership transfer, MFA, refresh-token/session management, trusted-proxy configuration, external security review, deployment automation, backup-restore drills, and a staging soak test remain open.
