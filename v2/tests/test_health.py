from fastapi.testclient import TestClient

from apps.api import main
from apps.api.request_limits import MAX_REQUEST_BODY_BYTES

client = TestClient(main.app)


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, _statement):
        return 1


class FakeEngine:
    def connect(self):
        return FakeConnection()

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
    monkeypatch.setattr(main, "Redis", FakeRedis)
    main.get_settings.cache_clear()

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {"postgres": "ok", "redis": "ok"},
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
