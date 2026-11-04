# M0 — Legacy application audit (initial static review)

**Scope:** public GitHub repository `hyper1-afk/SecureLinkApp`, default branch `main`, plus branch `securelink-v2`. This is a source review, not a penetration test, dependency audit, production configuration review, or certification. Findings below are preliminary and must be verified in a controlled local environment.

## Repository baseline
- Repository is public; default branch is `main`; current branch `securelink-v2` already existed before this scaffold.
- Legacy application is primarily Flask, SQLAlchemy, PostgreSQL/SQLite-compatible persistence, Gunicorn and Docker.
- Existing capabilities advertised in README include URL verification, domain health checks (SSL/SPF/DMARC), breach lookup, monitoring/watches, PDF reports, organization/team features, and browser extension/API integrations. Feature behavior and production reliability have not yet been independently validated.
- Existing code has useful detectors, provider integrations, auth and domain models. Reuse only after tests, threat review and data-contract mapping.

## Findings requiring action

### M0-01 — Credential hygiene / possible exposed API key
The committed `.env.example` contains a non-placeholder value for a Google Safe Browsing API-key setting. The value is intentionally not copied into this report. Treat it as compromised until proven otherwise: revoke/rotate it with the provider, review usage, search all Git history and artifacts for secrets, and move all credentials to a secret manager. Also inspect email/SMTP example values and repository history. A value in an example file may be real even if the filename says example.

**Priority:** Critical until the key is rotated and verified invalid.

### M0-02 — License inconsistency
README advertises MIT while the checked-in LICENSE text identifies itself as proprietary / all rights reserved. Do not assume the code is MIT-licensed or redistribute it under MIT until ownership and licensing are resolved. Obtain legal review and make README, LICENSE, package metadata and third-party notices consistent.

**Priority:** Release blocker.

### M0-03 — URL scanning boundary / SSRF review
The URL verifier uses external HTTP provider lookups and URL parsing. Complete a dedicated review of every path that fetches user-supplied URLs, redirect handling, DNS resolution, IPv4/IPv6 private/link-local/loopback/metadata ranges, DNS rebinding, IDNA normalization, ports, schemes, timeouts, response sizes and outbound egress. Do not fetch arbitrary submitted URLs from the API process. Use a restricted scanning worker with egress policy and revalidate every redirect and resolved address.

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
- Complete SSRF/URL-fetch threat model and isolated scanner design.
- Inventory agent subprocess capabilities and disable unsafe production paths.
- Review extension permissions/privacy and provider data-sharing behavior.
- Establish dependency/SBOM scan, secret scanning, SAST and baseline tests.
- Back up legacy data and demonstrate restore; no migration before mapping sign-off.
- Record feature inventory with tests and disposition: reuse, rewrite, retire.

## Evidence limitations
This document records source-level indicators and review priorities only. It does not claim an exploit was demonstrated, that production is compromised, or that any item has been remediated.
