# Authentication and tenant security review

This is an internal code review of the current V2 foundation, not an external penetration test or production approval.

## Implemented and exercised

- Passwords are Argon2-hashed. Unknown login addresses use a dummy hash check and the same public login error.
- Registration requires a verification link before login. Action tokens are random, single-use, expire, and are stored as SHA-256 digests.
- Password reset increments a token version, invalidating existing access tokens.
- Tokens require issuer, audience, expiry, subject, token ID and current version; disabled accounts are denied.
- Redis-backed fixed-window limits protect registration, verification, login and recovery. Redis failure returns 503 rather than disabling limits.
- Tenant lookups require a current user/organization membership. Cross-organization access is tested; owner/admin-only member listing is tested.
- PostgreSQL migration installs an append-only trigger for audit events; CI verifies update rejection against PostgreSQL.

## Open findings / release gates

1. **Proxy-aware rate limiting:** limits currently key on the ASGI client address. Verify that the deployment exposes the real client address safely. Configure trusted proxy ranges; never accept a caller-provided forwarded address from an untrusted source.
2. **Durable email delivery:** email sends run after the response in the API process. This reduces timing leaks but is not durable across process termination. Add a transactional outbox and worker with retries before production.
3. **Email link UI:** the V2 web app does not exist yet. Build verification/reset pages that immediately exchange the one-time token, remove it from browser history, set `Referrer-Policy: no-referrer`, and never include third-party scripts on token pages.
4. **Browser auth:** the legacy extension has not been integrated with V2. Design OAuth authorization code with PKCE, extension-specific scopes, and short-lived sessions before linking accounts.
5. **Authorization breadth:** role storage and owner/admin member listing exist. Invitation, role changes, last-owner protection, organization switching and permission matrices still need implementation and negative tests.
6. **Session controls:** password reset and account disable invalidate access tokens; logout/session revocation and refresh-token rotation are not implemented.
7. **Abuse/load testing:** CI tests a Redis rate limit against a live Redis service, but distributed load, multiple proxy hops, boundary bursts, and customer NAT behavior need staging validation.
8. **Operational recovery:** no staging deployment or restore drill has run. Validate SMTP, TLS, backup restoration, alerts, rollback, data retention and secret rotation in isolated DigitalOcean staging.

Do not treat passing CI as a complete security review or production readiness.
