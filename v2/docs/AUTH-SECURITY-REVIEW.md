# Authentication and tenant security review

Internal code review of the V2 foundation; this is not an external penetration test or production approval.

## Implemented and exercised

- Passwords use Argon2; unknown login addresses use a dummy hash check and the same public login error.
- Registration requires email verification. Action tokens are random, single-use, expire, and are stored as SHA-256 digests.
- Password-reset increments a token version, invalidating existing access tokens.
- Access tokens require issuer, audience, expiry, subject, token ID and current version; disabled accounts are denied.
- Redis-backed fixed-window limits protect registration, verification, login and recovery. Redis failure returns 503.
- Organization access checks current membership. Cross-organization access and owner/admin-only member listing are tested.
- PostgreSQL installs an append-only audit trigger; CI verifies update rejection against PostgreSQL.
- Account email is transactionally queued in PostgreSQL; the token delivery payload is encrypted and a separate worker leases, retries, and clears it after success.

## Open findings / release gates

1. **Proxy-aware rate limiting:** limits currently key on the ASGI client address. Configure trusted proxy ranges and test real client-IP behavior; never accept caller-supplied forwarded addresses from untrusted clients.
2. **Email link UI:** the V2 web app does not exist yet. Build verification/reset pages that immediately exchange the one-time token, remove it from browser history, set `Referrer-Policy: no-referrer`, and avoid third-party scripts on token pages.
3. **Browser auth:** the legacy extension is not integrated with V2. Design OAuth authorization code with PKCE, extension-specific scopes, and short-lived sessions before linking accounts.
4. **Authorization breadth:** invitation, role changes, last-owner protection, organization switching and permission matrices need implementation and negative tests.
5. **Session controls:** logout/session revocation and refresh-token rotation are not implemented.
6. **Abuse/load testing:** distributed load, proxy hops, rate-limit boundaries, and customer NAT behavior need staging validation.
7. **Operational recovery:** no staging deployment or restore drill has run. Validate SMTP, TLS, backup restoration, alerts, rollback, data retention and secret rotation in isolated DigitalOcean staging.

Do not treat passing CI as complete security review or production readiness.
