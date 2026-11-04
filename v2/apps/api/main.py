from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="SecureLink 2.0 API",
    version="0.1.0",
    description="Evidence-first security operations API",
)


class HealthResponse(BaseModel):
    status: str


@app.get("/health/live", response_model=HealthResponse, tags=["health"])
def liveness() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/health/ready", response_model=HealthResponse, tags=["health"])
def readiness() -> HealthResponse:
    # TODO(M1): verify PostgreSQL and Redis connectivity before reporting ready.
    return HealthResponse(status="starting")
