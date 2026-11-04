# security_core

Shared domain contracts live here; keep framework-specific code out.

Planned modules:
- evidence: immutable evidence references and provenance
- findings: normalized detector outputs and lifecycle
- risk: transparent, versioned risk scoring
- tenancy: organization context and authorization policy interfaces
- investigations: investigation state and audit trail

Do not put provider credentials, network clients, or LLM prompts in this package.
