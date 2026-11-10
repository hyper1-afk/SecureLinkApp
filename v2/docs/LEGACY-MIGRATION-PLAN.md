# Legacy to V2 migration plan

This plan keeps the running SecureLink application and its customers on the
legacy service while V2 is built and validated. There is no production cutover,
shared database, or dual-write path in this plan.

## Current data and capability boundary

The legacy application has a user-centered model with email, username, OAuth
provider identifiers, password hash and salt, subscription identifiers, and
optional monitored-mailbox settings. Its password verifier supports a current
PBKDF2-SHA256 format and a legacy SHA-256 format. Separate email-account records
may contain encrypted mailbox credentials. V2 uses organizations and
memberships, Argon2 password hashes, and a different security-event model. V2
does not yet provide billing or monitored-mailbox parity.

These differences mean that matching email addresses alone are not a safe
account or organization migration rule.

## Migration rules

- Keep the legacy site, API, database, billing, and automatic extension scan
  path operating independently until a measured retirement decision.
- Do not bulk-copy password hashes, session records, password-reset or email
  verification tokens, OAuth provider IDs, encrypted mailbox credentials, or
  Stripe identifiers. Each requires a separate security, compatibility, and
  customer-consent decision.
- Onboard existing users through a verified invitation and a fresh V2
  credential. Require a V2 organization owner to approve each membership; do
  not infer shared organization membership from a matching email domain.
- Keep legacy subscriptions authoritative until V2 billing and entitlement
  reconciliation exist. Do not charge a migrated customer twice or silently
  change their plan.
- Do not import old scan histories until retention, consent, evidence format,
  and deletion behavior have been mapped and approved. V2 scans create new,
  tenant-scoped evidence under V2's privacy rules.
- Do not transfer monitored-mailbox credentials. If mailbox monitoring returns
  to the product scope, customers must reconnect it through a separately
  reviewed, consented flow.
- Keep the existing extension's automatic legacy scanner intact. V2 extension
  access is an explicit, revocable connection for manual reviews; publishing
  that connector requires browser, privacy, and store-release checks.

## Staged sequence

1. **Preserve and inventory.** Keep production routing and the legacy database
   unchanged. Produce a read-only inventory from a protected staging copy:
   user counts, verified/unverified status, OAuth-only accounts, duplicate or
   malformed email addresses, subscription state, and separately stored
   monitored-mailbox records. Never place the export in Git or ordinary logs.
2. **Define the mapping.** Approve a field-by-field mapping for the chosen pilot
   cohort. Identify duplicate identities, owner assignment, invitation
   ownership, retention, and deletion behavior. Exclude fields without an
   approved V2 equivalent. Record expected source/destination counts.
3. **Dry-run onboarding.** Exercise verified invitations in isolated staging
   with synthetic accounts representing password, OAuth-only, unverified,
   duplicate-email, subscription, and multi-user cases. Verify invitation
   replay rejection, tenant isolation, audit events, and account recovery.
4. **Run an opt-in pilot.** Keep the legacy URL and extension flows available.
   Invite a small cohort to create or claim a V2 account, verify its email, and
   explicitly join the intended V2 organization. Link to V2 from the legacy
   site only after the staging URL, support text, and rollback destination are
   confirmed.
5. **Connect the extension separately.** Package V2 against its HTTPS staging
   origin, allowlist only that package's exact Chrome callback in staging, and
   test connect, consent, manual scan, disconnect, expiry, and server-side
   revocation. Do not change the store package or its legacy scanner during the
   pilot.
6. **Evaluate evidence before expanding.** Compare successful onboarding,
   first useful scan, weekly use, alert delivery, support contacts, and
   subscription continuity against the legacy cohort. Expand only after
   security review, restore testing, and product-owner approval.
7. **Retire only with a separate plan.** Announce a migration window, preserve
   customer access and billing, take and restore a final legacy backup, verify
   cohort completion, and keep a tested route back to the legacy service. DNS
   cutover and legacy shutdown are separate approval gates.

## Required gates before a production cohort

- A reviewed field map and dry-run report with reconciled counts and no
  unexplained duplicate or orphaned accounts.
- Successful invitation and account recovery tests for every supported legacy
  identity type, with no password-hash or session-token reuse.
- Security review of membership approval, tenant boundaries, audit records,
  extension scopes, and data-retention behavior.
- A verified database restore, measured recovery objectives, alert delivery
  test, and documented rollback owner.
- Staging extension tests in Chrome (and Edge if supported), exact OAuth
  callback allowlisting, and proof that the legacy extension path still works.
- Customer notice, support process, billing continuity, and an explicit
  production approval for that cohort.

Until these gates are evidenced, V2 remains a separate opt-in system and the
legacy application remains the production system of record.
