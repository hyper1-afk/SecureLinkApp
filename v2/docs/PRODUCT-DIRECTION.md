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

## Feature portfolio: acquisition hypotheses

These are directional scores for the chance a capability helps attract the intended customer, not measured conversion probabilities. Public threat-prevalence data is not a substitute for SecureLink signup, activation, retention, or payment data. Confidence is low until customer interviews and pilots validate the assumptions.

| Capability | Relative acquisition score | Confidence | V2 decision |
| --- | ---: | --- | --- |
| Link and phishing checks, including a browser extension | 5/5 | Medium | Keep as a clear entry point. Make the result fast, explainable, privacy-conscious, and honest about its limits. |
| Continuous verified-domain and external exposure monitoring | 4/5 | Medium | Core paid SMB value. Build after ownership verification and isolated, read-only checks. |
| Email inbox scanning | 4/5 | Low | Defer. Phishing is a clear pain, but mailbox OAuth scopes, data handling, and false positives create a high trust and support burden. |
| Domain health (TLS, SPF, DKIM, DMARC) | 3/5 | Low | Bundle into monitoring; weak as a standalone product. |
| Breach lookup with concrete response guidance | 3/5 | Low | Consider a partner-backed add-on only if it can show specific, safe next steps. Never accept or store plaintext passwords. |
| Compliance reporting | 3/5 | Low | Defer until a specific buyer segment and framework are validated; keeping mappings current is costly. |
| Alerting and concise digests | 3/5 for acquisition; 5/5 for retention | Low | Build with monitoring. Prioritize signal quality and customer-configurable thresholds over alert volume. |
| AI analyst | 2/5 standalone | Low | Treat as an evidence-grounded workflow assistant, not the product promise or an autonomous remediation agent. |
| Dark-web monitoring | 2/5 standalone | Medium | Remove from the V2 core and new V2 marketing. Revisit only as a partner-backed, actionable add-on after paid-customer validation. |
| PDF reports | 2/5 | Low | Defer; export findings after customers demonstrate a reporting need. |
| Security-news feed | 1/5 | Low | Remove from the V2 core; it is easy to copy and does not directly reduce a customer's risk. |
| Link shortener | 1/5 | Low | Remove from the V2 core; it adds abuse, reputation, and operational risks without strengthening the security-monitoring value proposition. |

### Why these choices

The UK Government's 2025/26 survey reports that 43% of businesses experienced a breach or attack, phishing affected 38% of businesses and was the most disruptive reported attack type, while 32% used security-monitoring tools. This indicates a material problem and a monitoring gap, but does not prove willingness to buy SecureLink. [Cyber Security Breaches Survey 2025/2026](https://www.gov.uk/government/statistics/cyber-security-breaches-survey-20252026/cyber-security-breaches-survey-20252026)

Verizon's 2026 DBIR reports that vulnerability exploitation was the initial entry point in 31% of breaches in its dataset. That supports prioritizing exposure and vulnerability workflows for SMB buyers after the safe asset-monitoring foundation exists. [Verizon 2026 DBIR summary](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds)

Dark-web alerts have a specific actionability problem: Google ended its Dark Web Report in 2026 and said user feedback showed that general reports did not give helpful next steps. This is a useful warning against selling alarming findings without clear response guidance; it is not proof that every breach-monitoring product lacks demand. [Google's discontinuation notice](https://support.google.com/websearch/answer/15191033?hl=en)

### Validation before investing further

Track landing-page conversion, account verification, first useful scan, repeat weekly use, paid conversion, churn, alert dismissals, and support time. Interview SMB operators and MSPs separately; consumer extension installs and B2B subscription demand are different markets. Change these rankings when SecureLink's own evidence contradicts the hypotheses.
