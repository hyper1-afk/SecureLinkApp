# SecureLink 2.0

SecureLink 2.0 is an evidence-first security operations platform developed separately from the legacy application at the repository root. Do not connect production customer data until the migration and security reviews are approved.

## Current API foundation

- Organization-scoped passive URL hygiene scans store redacted evidence and deterministic findings. They make no outbound network requests and do not produce malware/reputation verdicts.

- Email verification is required before login. A same-origin account page supports registration, sign-in, verification, resend, and password recovery.
- Password reset links are single-use, expire, and are stored as token digests. Delivery uses a database outbox with encrypted payloads and a separate retrying worker.
- Password reset and logout increment a token version and invalidate existing access tokens.
- Login and account lifecycle endpoints use Redis-backed IP rate limits and return 503 if Redis protection is unavailable.
- Organization access is checked against current membership on every request. Owners/admins can list members; owner/admin role changes and member removals are audited, with last-owner protection and stricter admin limits.
- Owners/admins can add domain assets, publish a one-time DNS TXT challenge, and verify control. Challenge values are returned once, marked no-store, kept only as digests, expire after 24 hours, and are removed after verification. Domain assets and audit events are organization-scoped.
- Analysts and admins can open an evidence-backed case from a scan with findings, then move it through a restricted, audited lifecycle. Tenant-scoped composite foreign keys keep findings attached only to cases in the same organization.
- The V2 API has a PKCE authorization-code flow for the Chrome extension, with exact redirect allowlisting, one-time codes, hashed opaque sessions, 12-hour expiry, scan-only scope, and individual session revocation. A separate unpacked V2 extension preview client is in `extension/`; it is not connected to the published extension. Local browser testing and staging validation remain release gates.
- Audit events are append-only in PostgreSQL.
- Access tokens expire after 15 minutes.

## Development

1. Install Git, Docker Desktop (WSL2 backend), and Python 3.12.
2. From PowerShell: `cd v2`
3. Generate a development-only environment file: `python scripts/init_local_env.py`. It creates unique secrets in `.env` and configures Mailpit for local email capture.
4. Start the local stack: `docker compose --profile local-mail up --build`.
5. Open the account page at http://localhost:8000, the Mailpit inbox at http://localhost:8025, API docs at http://localhost:8000/docs, and liveness at http://localhost:8000/health/live.
6. Verification, password-reset, and invitation emails are captured locally by Mailpit; no real mail is sent. This profile is for local development only.

SMTP must use STARTTLS. In production, the public URL must use HTTPS. Never commit populated secrets or use production credentials in local development.

The dashboard connects passive URL hygiene checks, domain verification, scan history, and the evidence-backed case lifecycle. The unpacked extension preview can submit manual scans to that same tenant-scoped scan and evidence pipeline. It does not yet schedule domain monitoring or automate investigations. Domain ownership verification performs only a bounded DNS TXT lookup; verifying ownership does not authorize arbitrary scanning and does not prove that resolved IP addresses are public. Any future collector must revalidate DNS answers and reject private/reserved IPs at execution time. Active URL fetching, third-party reputation checks, and automated response playbooks are not implemented; see [URL scan safety](docs/URL-SCAN-SAFETY.md).

V2 has no paid Have I Been Pwned account, breach, or domain API dependency, and requires no HIBP API key. Pwned Passwords has a separate free k-anonymity range service, but it is not currently integrated. Email breach lookup is deferred until there is a suitable source that meets cost, privacy, and data-licensing requirements.

## Workspace

- `apps/api`: HTTP API and application composition
- `packages/security_core`: identity and tenant data models
- `migrations`: Alembic migrations
- `docs`: [product direction](docs/PRODUCT-DIRECTION.md), architecture, threat model, staging runbook and extension redesign
- `tests`: unit, PostgreSQL migration and API tests

## Production status

Not production-ready. The account and email action pages plus a basic passive-scan dashboard are implemented; active scanning and the broader investigation workflows are not. Invitations to existing verified accounts are implemented. New-user invitation onboarding and ownership transfer, MFA, integration of the preview client into the published extension, trusted-proxy configuration, external security review, deployment automation, backup-restore drills, and a staging soak test remain open.
