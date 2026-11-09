import os
from uuid import uuid4

import pytest
from fastapi import HTTPException
from redis import Redis
from starlette.requests import Request

from apps.api import rate_limits


@pytest.mark.skipif(not os.getenv("REDIS_URL"), reason="Redis CI service is not configured")
def test_redis_rate_limit_enforces_shared_window(monkeypatch):
    url = os.environ["REDIS_URL"]
    probe = Redis.from_url(url, socket_connect_timeout=2)
    try:
        probe.ping()
    finally:
        probe.close()

    bucket = f"redis-integration-{uuid4()}"
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: Redis.from_url(url))
    dependency = rate_limits.rate_limit(bucket, 1, 60)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/auth/login",
            "client": ("192.0.2.20", 12345),
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )
    dependency(request)
    with pytest.raises(HTTPException) as raised:
        dependency(request)
    assert raised.value.status_code == 429
    assert int(raised.value.headers["Retry-After"]) > 0
