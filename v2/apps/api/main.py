from __future__ import annotations

from fastapi import FastAPI, Response, status
from pydantic import BaseModel
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from apps.api.auth import router as auth_router
from apps.api.config import get_settings


class HealthResponse(BaseModel):
    status: str
    checks: dict[str, str] | None = None


app = FastAPI(
    title="SecureLink 2.0 API",
    version="0.1.0",
    description="Evidence-first security operations API",
)
app.include_router(auth_router)


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
        client = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
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
