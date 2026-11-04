# Initial threat model

## Assets
Customer identities and credentials; tenant data; asset inventory; findings/evidence; integration tokens; AI prompts/responses; audit records; signing keys; deployment secrets.

## Trust boundaries
Browser/API; API/database; API/queue/worker; scanner/outbound network; AI provider/tool broker; SaaS control plane/customer self-hosted environment.

## Principal threats
- Cross-tenant access and insecure direct object references.
- SSRF, redirect abuse, DNS rebinding and cloud metadata access from scanners.
- Credential leakage in source, logs, prompts, reports or browser extension.
- Malicious scan content / prompt injection causing tool misuse or data exfiltration.
- Compromised integration credentials and excessive OAuth scopes.
- Queue poisoning, task replay, worker escape and resource exhaustion.
- Supply-chain compromise and vulnerable container/dependency images.
- Inadequate backups, audit tampering or sensitive-data over-retention.

## Required controls
Least privilege, server-side authorization, immutable audit events, short-lived scoped tokens, secret manager, egress allowlists, isolated scanning workers, request and resource limits, schema validation, signed artifacts, dependency scanning, log redaction, encrypted transport/storage, backup/restore drills and human approval for consequential actions.

## AI-specific controls
Untrusted data is quoted/structured as data, not instructions. Model has no direct database or shell access. Tools are allowlisted, read-only by default, schema-validated, organization-scoped and independently authorized. Require evidence citations and confidence/uncertainty. Reject unsupported claims and block secrets from model context unless explicitly required and authorized.
