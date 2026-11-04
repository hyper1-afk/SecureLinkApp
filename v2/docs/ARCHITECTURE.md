# SecureLink 2.0 architecture

## Core flow
Collectors and deterministic engines -> normalized observations -> immutable evidence -> findings -> investigation orchestration -> evidence-grounded analyst summary -> human decision.

The AI layer is an analyst assistant, not a detector of record. It may request approved read-only tools through a policy-enforced broker. Tool authorization is checked on every call against user, organization, role, asset scope and purpose. No model output can grant permissions or execute remediation.

## Initial bounded contexts
1. Identity & tenancy: users, organizations, memberships, roles, SSO and authorization.
2. Asset inventory: domains, IPs, cloud resources, endpoints and ownership.
3. Collection: scheduled scans and provider adapters with quotas and provenance.
4. Findings & evidence: normalized detections, immutable evidence records and deduplication.
5. Investigation: case state, timeline, correlations, analyst notes and decisions.
6. Risk: explainable scoring using severity, exposure, business context, exploitability and confidence.
7. AI analyst: provider-neutral model gateway, specialist workflows, tool broker and evaluation.
8. Reporting & notifications: signed/exportable reports, alerts and audit events.

## Tenant boundary
Every tenant-owned row has a non-null organization_id. API handlers derive organization context from authenticated membership, never from an untrusted request body alone. Database constraints and repository query helpers enforce tenant scope. Cross-tenant tests are mandatory.

## Evidence contract (planned)
Evidence records include id, organization_id, source_type, source_ref, observed_at, collected_at, content_hash, normalized_payload, collector_version and sensitivity. Preserve raw evidence where lawful and necessary; redact secrets and minimize personal data. Findings reference evidence IDs and detector/version metadata.

## Deployment profiles
- Cloud: shared control plane with strict tenant isolation; per-tenant data isolation options can be added for enterprise.
- Self-hosted: same signed application images, customer-managed secrets, local PostgreSQL/Redis, optional outbound integrations, and documented offline/degraded modes.
- Both profiles must expose the same API contract and migration lineage.
