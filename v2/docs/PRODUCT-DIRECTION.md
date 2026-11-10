# SecureLink product direction

## Product goal

Build a subscription security service for small organizations that continuously checks authorized assets, explains evidence in plain language, prioritizes actionable risks, and handles routine monitoring and notifications with little operator effort.

The product should support cloud SaaS and self-hosted deployments. SaaS is the first customer experience; self-hosted packaging and upgrade support follow the same security boundaries.

The service can reduce routine work, but it must not promise complete security or guaranteed revenue. Customers retain control of their assets, response policy, data, and billing.

## Product loop

1. A customer adds a URL, domain, or integration and confirms authority to monitor it.
2. SecureLink collects evidence through bounded, isolated checks.
3. Deterministic checks and reputation sources produce findings with timestamps, provenance, and uncertainty.
4. The product groups duplicate signals and ranks findings by severity, confidence, and asset context.
5. Customers receive a concise alert or digest with evidence, recommended next steps, and a link to review.
6. Safe maintenance tasks run automatically; consequential response remains under customer control.

A clean result must not be described as proof that an asset is safe. Every result should name the checks performed, their freshness, and any unavailable sources.

## Automation boundaries

### Automate by default

- Scheduled, read-only checks of customer-verified assets.
- Retries, deduplication, evidence retention according to customer policy, and report generation.
- Rate limiting, abuse prevention, service health alerts, billing retry workflows, and routine support triage.
- Notifications for new, changed, stale, or unresolved findings.

### Require explicit customer policy or approval

- Blocking users, links, domains, or network traffic.
- Changing DNS, certificates, cloud settings, access controls, or customer data.
- Disabling integrations or accounts, contacting third parties, or taking actions that can interrupt customer operations.
- Any AI-generated action beyond creating a draft recommendation.

The platform must preserve an audit trail and provide a safe pause/disable control for scheduled checks and automated notifications.

## Revenue model to validate

- SaaS subscriptions with clear monthly or annual plans.
- Entitlements based on monitored assets, seats, scan volume, history retention, and integrations.
- Paid self-hosted licensing and support as a separate offering.

Pricing, feature limits, retention periods, and any compliance claims need customer research and legal review. Do not advertise unfinished capabilities or imply that automated findings are a guarantee.

## Build sequence

### 1. Usable product interface

Turn the account scaffold into a customer dashboard for organizations, assets, scan history, findings, alert settings, and billing status. Keep the scan methodology and limitations visible.

### 2. Authorized asset inventory

Add organization-scoped assets, ownership verification, member permissions, audit records, and opt-in monitoring. Reject unverified or private-network targets.

### 3. Safe monitoring engine

Run checks in isolated workers with explicit egress policy, destination validation, time/size quotas, and tenant-scoped queues. Start with read-only domain hygiene and URL reputation. Do not fetch arbitrary URLs from the API process.

### 4. Findings and alert operations

Add finding lifecycle, deduplication, severity/confidence, notification preferences, quiet hours, email digests, and high-priority alert routing. Keep evidence immutable and give customers controls over retention.

### 5. Sustainable SaaS operations

Add subscription checkout, verified webhooks, entitlements, metering, cancellation/export, support tooling, billing recovery, and abuse controls. Test billing in provider sandbox before enabling charges.

### 6. Extension and integrations

Design browser OAuth authorization with PKCE, narrow permissions, token revocation, and a versioned API. Do not ship a long-lived secret in the extension.

### 7. Staging and production gates

Prove backup restore, alert delivery, incident response, capacity limits, security review, licensing, secret rotation, tenant isolation, and rollback in isolated staging. Only then consider a production launch.

## Current position

The current V2 has account and email flows, organization roles, audit events, a passive URL hygiene API, a basic scan dashboard, and a local Compose environment. It does not yet implement verified asset monitoring, reputation-based threat detection, the full customer dashboard, billing, or V2 extension integration. It is not production-ready.
