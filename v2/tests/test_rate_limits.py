import pytest
from fastapi import HTTPException
from starlette.requests import Request

from apps.api import rate_limits


class FakeRedis:
    def __init__(self):
        self.counts = {}

    def eval(self, _script, _key_count, key, _window):
        count = self.counts.get(key, 0) + 1
        self.counts[key] = count
        return [count, 30]

    def close(self):
        return None


def make_request(ip: str = "192.0.2.10") -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/auth/login",
            "client": (ip, 12345),
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


def test_rate_limit_returns_retry_after_after_limit(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)
    dependency = rate_limits.rate_limit("test", 2, 60)
    dependency(make_request())
    dependency(make_request())

    with pytest.raises(HTTPException) as raised:
        dependency(make_request())

    assert raised.value.status_code == 429
    assert raised.value.headers["Retry-After"] == "30"


def test_rate_limit_keys_are_isolated_by_client_ip(monkeypatch):
    redis = FakeRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)
    dependency = rate_limits.rate_limit("test", 1, 60)
    dependency(make_request("192.0.2.10"))
    dependency(make_request("192.0.2.11"))
