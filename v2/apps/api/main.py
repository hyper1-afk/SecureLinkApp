from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from apps.api.assets import router as assets_router
from apps.api.auth import router as auth_router
from apps.api.cases import router as cases_router
from apps.api.config import get_settings
from apps.api.extension_auth import router as extension_router
from apps.api.request_limits import RequestBodyLimitMiddleware
from apps.api.scanning import router as scanning_router
from apps.api.threat_intel import router as threat_intel_router


class HealthResponse(BaseModel):
    status: str
    checks: dict[str, str] | None = None


app = FastAPI(
    title="SecureLink 2.0 API",
    version="0.1.0",
    description="Evidence-first security operations API",
)
app.add_middleware(RequestBodyLimitMiddleware)
WEB_DIR = Path(__file__).with_name("web")
ACCOUNT_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; script-src 'self'; style-src 'self'; connect-src 'self'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}

app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(scanning_router)
app.include_router(threat_intel_router)
app.include_router(cases_router)
app.include_router(extension_router)
app.mount("/assets", StaticFiles(directory=WEB_DIR), name="account-assets")


@app.middleware("http")
async def prevent_response_caching(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def _account_page(filename: str) -> FileResponse:
    return FileResponse(WEB_DIR / filename, headers=ACCOUNT_HEADERS)


@app.get("/", include_in_schema=False)
def account_home() -> FileResponse:
    return _account_page("index.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page() -> FileResponse:
    return _account_page("dashboard.html")


@app.get("/verify-email", include_in_schema=False)
def verify_email_page() -> FileResponse:
    return _account_page("verify-email.html")


@app.get("/reset-password", include_in_schema=False)
def reset_password_page() -> FileResponse:
    return _account_page("reset-password.html")


@app.get("/accept-invitation", include_in_schema=False)
def accept_invitation_page() -> FileResponse:
    return _account_page("accept-invitation.html")


@app.get("/extension/authorize", include_in_schema=False)
def extension_authorize_page() -> FileResponse:
    return _account_page("extension-authorize.html")


@app.get("/health/live", response_model=HealthResponse, tags=["health"])
def liveness() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/health/ready", response_model=HealthResponse, tags=["health"])
def readiness(response: Response) -> HealthResponse:
    settings = get_settings()
    checks: dict[str, str] = {}

    try:
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError, TimeoutError):
        checks["postgres"] = "unavailable"

    try:
        redis_options = {"socket_connect_timeout": 2, "socket_timeout": 2}
        if settings.redis_url.lower().startswith("rediss://"):
            redis_options.update(ssl_cert_reqs="required", ssl_check_hostname=True)
        client = Redis.from_url(settings.redis_url, **redis_options)
        try:
            client.ping()
            checks["redis"] = "ok"
        finally:
            client.close()
    except (RedisError, OSError, TimeoutError):
        checks["redis"] = "unavailable"

    ready = all(value == "ok" for value in checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(status="ok" if ready else "not_ready", checks=checks)
