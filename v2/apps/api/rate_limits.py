from __future__ import annotations

import hashlib
from collections.abc import Callable

from fastapi import HTTPException, Request
from redis import Redis
from redis.exceptions import RedisError

from apps.api.config import get_settings

INCREMENT_WINDOW_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('TTL', KEYS[1])}
"""


def get_rate_limit_client() -> Redis:
    return Redis.from_url(
        get_settings().redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
    )


def rate_limit(bucket: str, maximum: int, window_seconds: int) -> Callable[[Request], None]:
    def enforce(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        key_material = f"{bucket}:{request.url.path}:{client_ip}"
        key_hash = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        client = get_rate_limit_client()
        try:
            count, ttl = client.eval(
                INCREMENT_WINDOW_SCRIPT,
                1,
                f"securelink:rate:v1:{key_hash}",
                window_seconds,
            )
        except (RedisError, OSError) as exc:
            raise HTTPException(status_code=503, detail="Request protection is unavailable") from exc
        finally:
            client.close()

        if int(count) > maximum:
            retry_after = max(1, int(ttl))
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(retry_after)},
            )

    return enforce
