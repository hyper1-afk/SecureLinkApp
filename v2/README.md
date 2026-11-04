# SecureLink 2.0

SecureLink 2.0 is a ground-up, evidence-first security operations platform. The legacy application remains intact at the repository root while V2 is developed in this isolated workspace.

## Development principles
- Detection engines and integrations produce facts; AI correlates, explains, and recommends.
- Every conclusion links to evidence, source, observation time, and confidence.
- AI tools are permission-scoped and read-only by default. No autonomous remediation or privilege elevation.
- Every tenant-owned record is organization-scoped and authorization is enforced server-side.
- Cloud and self-hosted deployments share one application image and configuration contract.

## Initial stack
- API: Python 3.12, FastAPI, Pydantic, SQLAlchemy 2, Alembic
- Data: PostgreSQL 16; Redis 7 for queues, caching, and distributed limits
- Jobs: Celery (worker boundary to be added after API foundations)
- Web: Next.js + TypeScript (separate app, next milestone)
- Search: OpenSearch adapter planned; do not make it a source of truth
- Observability: structured logs, OpenTelemetry hooks, health/readiness endpoints
- Packaging: Docker Compose for Windows development and self-hosted deployment

## Windows quick start
1. Install Git, Docker Desktop (WSL2 backend), and Python 3.12.
2. Open this repository in VS Code.
3. From PowerShell: `cd v2`
4. Copy config: `Copy-Item .env.example .env`
5. Set a unique `APP_SECRET_KEY` and local database password in `.env`.
6. Start dependencies and API: `docker compose up --build`
7. API docs: http://localhost:8000/docs; liveness: http://localhost:8000/health/live.

Never put production credentials in this file or commit a populated .env.

## Workspace
- `apps/api`: HTTP API and application composition
- `packages/security_core`: domain contracts and security primitives
- `docs`: audit, architecture, threat model and decisions
- `infra`: deployment configuration
- `tests`: automated tests

## Status
M0 audit and scaffold only. No production traffic, legacy database, or live deployment is connected. Do not migrate customer data until the legacy audit and migration plan are approved.
