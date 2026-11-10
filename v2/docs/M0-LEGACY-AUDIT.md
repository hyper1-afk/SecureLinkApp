# M0 — Legacy application audit (initial static review)

**Scope:** public GitHub repository `hyper1-afk/SecureLinkApp`, default branch `main`, plus branch `securelink-v2`. This is a source review, not a penetration test, dependency audit, production configuration review, or certification. Findings below are preliminary and must be verified in a controlled local environment.

## Repository baseline
- Repository is public; default branch is `main`; current branch `securelink-v2` already existed before this scaffold.
- Legacy application is primarily Flask, SQLAlchemy, PostgreSQL/SQLite-compatible persistence, Gunicorn and Docker.
- Existing capabilities advertised in README include URL verification, domain health checks (SSL/SPF/DMARC), breach lookup, monitoring/watches, PDF reports, organization/team features, and browser extension/API integrations. Feature behavior and production reliability have not yet been independently validated.
- Existing code has useful detectors, provider integrations, auth and domain models. Reuse only after tests, threat review and data-contract mapping.

## Findings requiring action

### M0-01 — Confirmed exposed Google Safe Browsing API key
The tracked `.env.example` contained a non-placeholder Google Safe Browsing API key. The value is intentionally not copied into this report. It has been cleared from the current working-tree version, but Git history confirms it was committed in `ed287bf` and remains in branch history. Treat it as compromised: revoke/rotate it with Google Cloud, review usage, search all refs and build artifacts for secrets, and verify the old key is invalid. Do not rewrite the active production branch as part of this remediation without a coordinated deployment plan. The other credential-like values in `.env.example` were checked and are placeholders; keep all actual credentials out of tracked files.

**Status:** Open until provider-side rotation, usage review, and invalidation are verified. The old key remains in repository history. The Gitleaks workflow's passing result is not evidence that this historical credential is invalid; a separate full-history pattern guard now makes CI fail while a Google API key-shaped value remains on fetched refs.

**Priority:** Critical until the key is rotated and verified invalid.

### M0-02 — License inconsistency
README previously advertised MIT and open-source self-hosting while the checked-in LICENSE is proprietary. The README now matches the proprietary LICENSE and says self-hosting requires a separate written commercial license. Inventory third-party notices and have counsel review the commercial license before distributing self-hosted packages.

**Status:** Repository messaging aligned; commercial license and third-party attribution review remain.

**Priority:** Release blocker for self-hosted distribution until those terms are reviewed.

### M0-03 — URL scanning boundary / SSRF review
The anonymous legacy health-check routes passed user-supplied domains into TLS, HTTP-header, page-content and TCP-port probes. The `securelink-v2` branch now validates and pins public DNS answers for HTTP/TLS probes, rejects private/non-global addresses, disables redirects and bounds HTTP headers and response bodies. TCP port probing is disabled in the shared web process, and the UI/PDF call the resulting score partial. A focused regression suite covers private/mixed DNS results, pinned connections, redirects and response-size bounds.

This is a targeted source-level remediation, not a complete SSRF sign-off. Review all active routes and integrations in a controlled local environment; deploy probes only in an isolated worker with enforceable egress rules; then test metadata, IPv4/IPv6, DNS rebinding, proxy configuration and redirect behavior end to end. V2's current scanner remains passive.

**Status:** Initial code remediation on `securelink-v2`; focused tests pass locally. Full review and isolated-worker/e2e validation remain open.

**Priority:** Critical before exposing URL fetch functionality.

### M0-04 — Tenant isolation
The legacy schema includes organization identifiers, but nullable organization fields and broad route surface require a complete authorization matrix. Verify every query, update, export, background task and object lookup is scoped to the authenticated organization; add cross-tenant negative tests. Enforce ownership in service/repository boundaries, not only UI filters.

**Priority:** Critical before multi-tenant SaaS.

### M0-05 — Rate limiting and proxy trust
Legacy Flask configuration includes in-memory rate-limit storage. This does not coordinate across multiple workers/instances. Use Redis-backed limits. Review client IP derivation and only trust forwarded headers from explicitly configured reverse proxies; clients must not be able to spoof rate-limit identity.

**Priority:** High.

### M0-06 — Agent subprocess isolation
Legacy agent scheduler starts subprocesses from the application environment and uses a watchdog timeout. Timeout alone is not a security boundary. Inventory commands, arguments, filesystem access, environment inheritance, network access, process tree termination and user-controlled inputs. Move jobs to isolated workers with least privilege, restricted mounts/egress, resource limits and signed/allowlisted task definitions. Disable autonomous code-modifying agent workflows in customer-facing production.

**Priority:** Critical if reachable in production.

### M0-07 — AI provider coupling and prompt injection
At least one attack-surface route calls a specific Claude model directly. Replace direct provider calls with a provider-neutral interface. Treat scan output, web pages, DNS records, certificates, emails and uploaded files as untrusted data; they must never become instructions. Require structured outputs tied to evidence IDs, validate every tool call in policy code, and require human approval for sensitive actions.

**Priority:** High.

### M0-08 — Browser extension permissions/privacy
Review manifest host permissions and every content/background script. Minimize permissions, collect only disclosed necessary metadata, avoid transmitting page content or credentials, and document retention and user controls. Validate message origin and extension-to-API authentication.

**Priority:** High before extension release.

### M0-09 — Migration strategy
Legacy startup code appears to perform schema adjustments at runtime. V2 will use versioned Alembic migrations, explicit backup/restore tests, migration dry runs and a separately reviewed mapping. Never point V2 at the production database during development.

**Priority:** High.

### M0-10 — Deployment and operational controls
Review Docker Compose, proxy headers, TLS termination, container privileges, health checks, backups, restore drills, log redaction, alerting, dependency pinning and image provenance. The Dockerfile has a HEALTHCHECK and a final Gunicorn CMD; verify health-check behavior and runtime command in built image. Separate SaaS and self-hosted secret/configuration profiles.

**Priority:** High.

### M0-11 — Documentation and claims
README feature/plan claims and public-facing product claims must be reconciled with tested behavior and current store listings. Remove unsupported ratings, customer counts, scan limits or security guarantees unless independently substantiated.

**Priority:** Medium.

## M0 exit criteria
- Rotate/revoke any committed credentials and complete a full history scan.
- Resolve license ownership and choose one valid license.
- Produce route-to-role/tenant authorization matrix and cross-tenant test suite.
- Complete SSRF/URL-fetch threat model and isolated scanner design; validate the legacy remediation end to end.
- Inventory agent subprocess capabilities and disable unsafe production paths.
- Review extension permissions/privacy and provider data-sharing behavior.
- Establish dependency/SBOM scan, secret scanning, SAST and baseline tests.
- Back up legacy data and demonstrate restore; no migration before mapping sign-off.
- Record feature inventory with tests and disposition: reuse, rewrite, retire.

## Evidence limitations
This document records source-level indicators and review priorities only. It does not claim an exploit was demonstrated, that production is compromised, or that any item has been remediated.
