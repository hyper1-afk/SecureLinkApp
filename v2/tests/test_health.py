from fastapi.testclient import TestClient

from apps.api import main
from apps.api.request_limits import MAX_REQUEST_BODY_BYTES

client = TestClient(main.app)


class FakeResult:
    def __init__(self, schema_revision: str):
        self.schema_revision = schema_revision

    def scalars(self):
        return self

    def all(self):
        return [self.schema_revision]


class FakeConnection:
    def __init__(self, schema_revision: str = "test-head"):
        self.schema_revision = schema_revision

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, statement):
        if "alembic_version" in str(statement):
            return FakeResult(self.schema_revision)
        return FakeResult(self.schema_revision)


class FakeEngine:
    def __init__(self, schema_revision: str = "test-head"):
        self.schema_revision = schema_revision

    def connect(self):
        return FakeConnection(self.schema_revision)

    def dispose(self):
        return None


class FakeRedis:
    @classmethod
    def from_url(cls, *_args, **_kwargs):
        return cls()

    def ping(self):
        return True

    def close(self):
        return None


def test_liveness_is_independent_of_dependencies():
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_responses_include_baseline_security_headers():
    response = client.get("/health/live")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


def test_oversized_request_body_is_rejected_before_route_processing():
    response = client.post(
        "/auth/register",
        content=b"x" * (MAX_REQUEST_BODY_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_oversized_chunked_request_body_is_rejected():
    def chunks():
        yield b"x" * MAX_REQUEST_BODY_BYTES
        yield b"x"

    response = client.post(
        "/auth/register",
        content=chunks(),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413


def test_readiness_reports_healthy_dependencies(monkeypatch):
    monkeypatch.setattr(main, "create_engine", lambda *args, **kwargs: FakeEngine())
    monkeypatch.setattr(main, "_migration_heads", lambda: frozenset({"test-head"}))
    monkeypatch.setattr(main, "Redis", FakeRedis)
    main.get_settings.cache_clear()

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {"postgres": "ok", "schema": "ok", "redis": "ok"},
    }


def test_readiness_fails_closed_when_database_schema_is_behind(monkeypatch):
    monkeypatch.setattr(main, "create_engine", lambda *args, **kwargs: FakeEngine("old-head"))
    monkeypatch.setattr(main, "_migration_heads", lambda: frozenset({"test-head"}))
    monkeypatch.setattr(main, "Redis", FakeRedis)
    main.get_settings.cache_clear()

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"] == {
        "postgres": "ok", "schema": "migration_required", "redis": "ok",
    }


def test_readiness_fails_closed_when_database_is_unavailable(monkeypatch):
    def fail_engine(*_args, **_kwargs):
        raise OSError("database unavailable")

    monkeypatch.setattr(main, "create_engine", fail_engine)
    monkeypatch.setattr(main, "Redis", FakeRedis)
    main.get_settings.cache_clear()

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"]["postgres"] == "unavailable"
    assert response.json()["checks"]["redis"] == "ok"

