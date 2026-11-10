# Authentication and tenant security review

Internal code review of the V2 foundation; this is not an external penetration test or production approval.

## Implemented and exercised

- Passwords use Argon2; unknown login addresses use a dummy hash check and the same public login error.
- Registration requires email verification. Action tokens are random, single-use, expire, and are stored as SHA-256 digests.
- Password-reset increments a token version, invalidating existing access tokens.
- Access tokens require issuer, audience, expiry, subject, token ID and current version; disabled accounts are denied.
- Redis-backed fixed-window limits protect registration, verification, login and recovery. Redis failure returns 503.
- Organization access checks current membership. Cross-organization access and owner/admin-only member listing are tested. Owner/admin member role changes and removals are audited; admins cannot manage owners/admins, and the last owner cannot be demoted or removed.
- PostgreSQL installs an append-only audit trigger; CI verifies update rejection against PostgreSQL.
- Account email is transactionally queued in PostgreSQL; the token delivery payload is encrypted and a separate worker leases, retries, and clears it after success.
- The first URL scan is passive and makes no network requests. URLs are redacted before persistence; evidence and findings are organization-scoped and PostgreSQL scan evidence is immutable.
- The V2 extension OAuth server flow requires PKCE S256 and an exact configured Chrome redirect URI. Codes and opaque 12-hour session tokens are stored only as hashes; extension sessions can call only the scoped scan and revoke endpoints. Password reset/account deactivation invalidate sessions through the user token version.

## Open findings / release gates

1. **Trusted proxy deployment configuration:** rate limits honor `X-Forwarded-For` only when the immediate peer is inside explicitly configured `TRUSTED_PROXY_CIDRS`; without configured ranges the direct peer address is used. Before staging, obtain DigitalOcean’s actual app ingress ranges and verify the full forwarded chain behavior; do not guess ranges.
2. **Product workflows:** the account page supports registration, sign-in, verification and recovery. A basic authenticated dashboard supports passive URL analysis and tenant-scoped history; active scanning, reputation verdicts, and broader investigations are not implemented. Account and dashboard pages use `no-store`/`no-referrer` headers under a restrictive CSP. Account action links use URL fragments and remove them from history before exchange.
3. **Browser auth:** the legacy extension client is not integrated with V2. Implement and test its PKCE flow with `chrome.identity.launchWebAuthFlow`, state verification, `chrome.storage.session`, and API host permission prompts before connecting the published item. The server currently allowlists only the published Chrome redirect; staging OAuth cannot be exercised from the extension until its staging API origin is configured.
4. **Authorization breadth:** invitations to existing verified accounts are implemented and tested. New-user invitation onboarding, ownership transfer, organization switching, and a complete permission matrix need implementation and negative tests.
5. **Session controls:** web logout revokes all of a user's current access tokens and extension sessions through a token-version increment. Users can list and revoke their own extension sessions through the dashboard. Refresh tokens are intentionally not issued.
6. **Abuse/load testing:** distributed load, proxy hops, rate-limit boundaries, and customer NAT behavior need staging validation.
7. **Operational recovery:** no staging deployment or restore drill has run. Validate SMTP, TLS, backup restoration, alerts, rollback, data retention and secret rotation in isolated DigitalOcean staging.

Do not treat passing CI as complete security review or production readiness.
