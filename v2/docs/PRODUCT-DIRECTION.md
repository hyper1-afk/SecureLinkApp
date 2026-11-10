# SecureLink product direction

## Product goal

Build SecureLink into an automated SOC service for small organizations: continuously ingest signals from authorized assets and existing SecureLink products, detect and correlate threats, investigate them with evidence, prioritize cases, and carry out approved response playbooks. Routine operations should require little operator effort; consequential changes remain behind customer-controlled approval policies.

The product should support cloud SaaS and self-hosted deployments. SaaS is the first customer experience; self-hosted packaging and upgrade support follow the same security boundaries. Preserve the existing website and browser-extension experience while V2 is built and validated separately.

SecureLink already has a reported base of 400+ browser-extension installs and active website users. Treat that as meaningful product traction, but distinguish installs from active use, retention, and paid conversion. Before retiring a live capability, measure its use and migration impact. V2 can remove low-value scope without silently removing features from existing users.

The service can reduce routine work, but it must not promise complete security or guaranteed revenue. Customers retain control of their assets, response policy, data, and billing.

## Product loop

1. SecureLink receives a signal from the browser extension, a customer-authorized asset, or an enabled integration.
2. Isolated collectors preserve evidence, provenance, timestamps, and uncertainty.
3. Detection rules enrich and correlate related signals into a tenant-scoped case.
4. Automated triage prioritizes the case and drafts investigation findings and response steps.
5. SecureLink runs low-risk playbooks under customer policy and requests approval for high-impact actions.
6. The customer receives a concise case update and an audit trail of evidence, decisions, and actions.

A clean result must not be described as proof that an asset is safe. Every result should name the checks performed, their freshness, and any unavailable sources.

## Automation boundaries

### Automate by default

- Scheduled, read-only checks of customer-verified assets and signals explicitly enabled by the customer.
- Evidence normalization, deduplication, enrichment, case correlation, severity/confidence scoring, and routine triage drafts.
- Retries, evidence retention according to customer policy, routine reports, rate limiting, abuse prevention, and service-health alerts.
- Customer-configured notifications, digests, and low-risk response playbooks with clear audit records.

### Require explicit customer policy or approval

- Blocking users, links, domains, or network traffic unless an explicit customer playbook authorizes that exact action and scope.
- Changing DNS, certificates, cloud settings, access controls, or customer data.
- Disabling integrations or accounts, contacting third parties, or taking actions that can interrupt customer operations.
- AI-generated actions outside a narrowly defined, tested, customer-approved playbook.

The platform must preserve an audit trail and provide a safe pause/disable control for scheduled checks and automated notifications.

## Revenue model to validate

- SaaS subscriptions with clear monthly or annual plans.
- Entitlements based on monitored assets, seats, scan volume, history retention, and integrations.
- Paid self-hosted licensing and support as a separate offering.

Pricing, feature limits, retention periods, and any compliance claims need customer research and legal review. Do not advertise unfinished capabilities or imply that automated findings are a guarantee.

## Build sequence

### 1. Foundation and SOC case model

Finish tenant isolation, session and permission review, ownership verification, immutable evidence, auditability, job scheduling, queue isolation, secrets management, and operational observability. Establish a case model that relates signals, evidence, assets, severity, confidence, status, owner, and response history. Keep the scan methodology and limitations visible.

### 2. Preserve and connect the existing product

Keep the current website scanning and browser extension as the user-facing entry point. Connect those existing users and signals to the V2 account, case, and alert model through a versioned API and secure OAuth/PKCE flow. Measure active usage, retention, false positives, and paid conversion before removing any live capability.

### 3. Authorized asset inventory and safe collectors

Add organization-scoped assets, ownership verification, member permissions, audit records, and opt-in monitoring. Run checks in isolated workers with explicit egress policy, destination validation, time/size quotas, and tenant-scoped queues. Reject unverified or private-network targets. Do not fetch arbitrary URLs from the API process.

### 4. Detection, investigation, and response playbooks

Build finding lifecycle, deduplication, severity/confidence, evidence-grounded investigation, notification preferences, quiet hours, email digests, and high-priority alert routing. Start with phishing/link threats and authorized domain exposure. Add integrations and further detection sources only when they improve case outcomes. Keep evidence immutable and give customers controls over retention.

### 5. Usable SOC console and sustainable SaaS operations

Turn the existing account scaffold into a case-centered dashboard for organizations, assets, alerts, investigation history, playbooks, and billing. Add subscription checkout, verified webhooks, entitlements, metering, cancellation/export, support tooling, billing recovery, and abuse controls. Test billing in provider sandbox before enabling charges.

### 6. Additional SOC integrations and self-hosted packaging

Add additional log, identity, email, and cloud integrations according to customer demand and privacy review. Support the existing extension through browser OAuth authorization with PKCE, narrow permissions, token revocation, and a versioned API. Do not ship a long-lived secret in the extension. Prepare self-hosted packaging after SaaS operations are stable.

### 7. Staging and production gates

Prove backup restore, alert delivery, incident response, capacity limits, security review, licensing, secret rotation, tenant isolation, and rollback in isolated staging. Only then consider a production launch.

## Current position

The current V2 has account and email flows, organization roles, audit events, a passive URL hygiene API, a basic scan dashboard, a local Compose environment, and the first domain asset inventory slice with DNS ownership verification. Ownership verification does not itself run monitoring. V2 does not yet implement isolated monitoring jobs, reputation-based threat detection, correlated cases, automated investigation, the full SOC dashboard, billing, or V2 extension integration. It is not production-ready.

## Feature portfolio: acquisition hypotheses

These are directional scores for the chance a capability helps attract the intended customer, not measured conversion probabilities. Public threat-prevalence data is not a substitute for SecureLink signup, activation, retention, or payment data. Confidence is low until customer interviews and pilots validate the assumptions.

| Capability | Relative acquisition score | Confidence | V2 decision |
| --- | ---: | --- | --- |
| Existing website scanner and browser extension | 5/5 | Medium, strengthened by 400+ reported installs and current users | Preserve and improve as a proven entry point; instrument active use and connect findings to cases. |
| Automated SOC cases, alerting, and approved playbooks | 5/5 for retention and paid value | Low until paid pilots | Core destination. Automate routine triage and customer-approved actions; require approval for consequential response. |
| Continuous verified-domain and external exposure monitoring | 4/5 | Medium | Build as a detection source after ownership verification and isolated, read-only checks. |
| Existing email-link monitoring | 4/5 | Low | Preserve pending usage review; improve consent, credential handling, and signal quality before expanding mailbox access. |
| Domain health (TLS, SPF, DKIM, DMARC) | 3/5 | Low | Bundle into monitoring; weak as a standalone product. |
| Breach lookup with concrete response guidance | 3/5 | Low | Consider a partner-backed add-on only if it can show specific, safe next steps. Never accept or store plaintext passwords. |
| Compliance reporting | 3/5 | Low | Defer until a specific buyer segment and framework are validated; keeping mappings current is costly. |
| Alerting and concise digests | 3/5 for acquisition; 5/5 for retention | Low | Build with monitoring. Prioritize signal quality and customer-configurable thresholds over alert volume. |
| AI analyst | 2/5 standalone | Low | Treat as an evidence-grounded workflow assistant, not the product promise or an autonomous remediation agent. |
| Dark-web monitoring | 2/5 as a standalone alert feed | Medium | Do not build generic alerts as a separate product. Keep actionable, well-sourced exposure signals eligible for SOC case correlation if they include verifiable evidence and safe next steps. |
| PDF reports | 2/5 | Low | Defer; export findings after customers demonstrate a reporting need. |
| Security-news feed | 1/5 | Low | Remove from the V2 build scope; it does not directly investigate or reduce customer risk. |
| Link shortener | 1/5 | Low | Remove from the V2 build scope; it adds abuse, reputation, and operational work without strengthening SOC outcomes. |
| Community/forum and standalone threat-map content | 1/5 | Low | Do not rebuild as separate V2 products. Retain only customer-submitted intelligence that can be validated and safely enrich detections. |

### Why these choices

The UK Government's 2025/26 survey reports that 43% of businesses experienced a breach or attack, phishing affected 38% of businesses, and 32% used specific tools designed for security monitoring. The same survey says 52% of businesses did at least one of six risk-identification activities. The 32% figure does not mean the other businesses reject security products, and it is not SecureLink conversion data. SecureLink's reported installs and existing users are more directly relevant traction, but still need active-use, retention, and revenue measurements. [Cyber Security Breaches Survey 2025/2026](https://www.gov.uk/government/statistics/cyber-security-breaches-survey-20252026/cyber-security-breaches-survey-20252026)

Verizon's 2026 DBIR reports that vulnerability exploitation was the initial entry point in 31% of breaches in its dataset. That supports prioritizing exposure and vulnerability workflows for SMB buyers after the safe asset-monitoring foundation exists. [Verizon 2026 DBIR summary](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds)

Dark-web alerts have a specific actionability problem: Google ended its Dark Web Report in 2026 and said user feedback showed that general reports did not give helpful next steps. This is a useful warning against selling alarming findings without clear response guidance; it is not proof that every breach-monitoring product lacks demand. [Google's discontinuation notice](https://support.google.com/websearch/answer/15191033?hl=en)

### Validation before investing further

Track landing-page conversion, account verification, first useful scan, repeat weekly use, paid conversion, churn, alert dismissals, and support time. Interview SMB operators and MSPs separately; consumer extension installs and B2B subscription demand are different markets. Change these rankings when SecureLink's own evidence contradicts the hypotheses.
