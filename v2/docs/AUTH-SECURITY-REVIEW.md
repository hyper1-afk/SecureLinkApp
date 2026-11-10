# Authentication and tenant security review

Internal code review of the V2 foundation; this is not an external penetration test or production approval.

## Implemented and exercised

- Passwords use Argon2; unknown login addresses use a dummy hash check and the same public login error. TOTP MFA uses separately encrypted secrets, single-use hashed recovery codes, rate-limited enrollment and disable actions, and token-version revocation when disabled. Owners/admins have seven days from privileged-role assignment to enroll; privileged web/API and extension access is denied after the deadline, and active privileged members cannot disable MFA. Both web and extension OAuth sign-in accept MFA codes.
- Registration requires email verification. Action tokens are random, single-use, expire, and are stored as SHA-256 digests.
- Password-reset increments a token version, invalidating existing access tokens.
- Access tokens require issuer, audience, expiry, subject, token ID and current version; disabled accounts are denied.
- Redis-backed fixed-window limits protect registration, verification, login and recovery. Redis failure returns 503.
- Organization access checks current membership. Cross-organization access and owner/admin-only member listing are tested. Owner/admin member role changes and removals are audited; admins cannot manage owners/admins, and the last owner cannot be demoted or removed. Ownership transfer is restricted to the current owner, requires password and MFA reauthentication, targets an existing admin, and is audited. Invitations support both verified accounts and new invitees, use single-use email action tokens, require new invitees to set a password, and audit invitation creation and acceptance.
- PostgreSQL installs an append-only audit trigger; CI verifies update rejection against PostgreSQL.
- Account email is transactionally queued in PostgreSQL; the token delivery payload is encrypted and a separate worker leases, retries, and clears it after success.
- The first URL scan is passive and makes no network requests. URLs are redacted before persistence; evidence and findings are organization-scoped and PostgreSQL scan evidence is immutable.
- High/critical deterministic URL indicators open an audited, tenant-scoped case and queue email alerts in the same transaction as the scan. Only verified, active owners/admins with alerts enabled are recipients. The worker rechecks current membership and preference before sending, uses leased retries, and logs no recipient or submitted URL. Owners/admins can view tenant-scoped pending/failed counts; messages contain the hostname and dashboard link, not URL path/query. An SMTP timeout after acceptance can still cause duplicate delivery.
- The V2 extension OAuth server flow requires PKCE S256 and an exact configured Chrome redirect URI. Codes and opaque 12-hour session tokens are stored only as hashes; extension sessions can call only the scoped scan and revoke endpoints. Password reset/account deactivation invalidate sessions through the user token version.

## Open findings / release gates

1. **Trusted proxy deployment configuration:** rate limits honor `X-Forwarded-For` only when the immediate peer is inside explicitly configured `TRUSTED_PROXY_CIDRS`; without configured ranges the direct peer address is used. Before staging, obtain DigitalOcean’s actual app ingress ranges and verify the full forwarded chain behavior; do not guess ranges.
2. **Product workflows:** the account page supports registration, sign-in, verification and recovery. A basic authenticated dashboard supports passive URL analysis and tenant-scoped history; active scanning, reputation verdicts, and broader investigations are not implemented. Account and dashboard pages use `no-store`/`no-referrer` headers under a restrictive CSP. Account action links use URL fragments and remove them from history before exchange.
3. **Browser auth:** the development branch adds an opt-in V2 connector to the existing extension and a separate unpacked preview. The connector requests the optional Chrome `identity` permission only after a user clicks Connect, uses PKCE state/code verification and session-scoped token storage, and submits manual reviews only. The published item has not been updated. Load the development extension package, allowlist its exact callback, and exercise connection, scan, server-side revocation, and local disconnect in Chrome before staging. Preserve existing automatic checks and pass store review before release.
4. **Authorization breadth:** invitations to existing and new accounts, authenticated organization listing/switching, and MFA-protected ownership transfer are implemented and tested. A complete permission matrix needs further negative tests.
5. **MFA policy:** Seven-day owner/admin enrollment grace, post-deadline API/extension denial, and MFA disable prevention are implemented. CI covers deadline enforcement and recovery-code sign-in. Assisted recovery when every authenticator and recovery code is lost still needs an approved, dual-control support runbook and staging exercise.
6. **Session controls:** web logout revokes all of a user's current access tokens and extension sessions through a token-version increment. Users can list and revoke their own extension sessions through the dashboard. Refresh tokens are intentionally not issued.
7. **Abuse/load testing:** distributed load, proxy hops, rate-limit boundaries, and customer NAT behavior need staging validation.
8. **Operational recovery:** no staging deployment or restore drill has run. Validate SMTP, TLS, backup restoration, alerts, rollback, data retention and secret rotation in isolated DigitalOcean staging.

Do not treat passing CI as complete security review or production readiness.
