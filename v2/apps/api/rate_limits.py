from __future__ import annotations

import hashlib
import ipaddress
from functools import lru_cache
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


@lru_cache(maxsize=32)
def _trusted_networks(configured: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for value in configured.split(","):
        cidr = value.strip()
        if not cidr:
            continue
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as exc:
            raise RuntimeError("Invalid trusted proxy CIDR configuration") from exc
    return tuple(networks)


def _is_trusted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _client_address(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return "unknown"

    trusted_networks = _trusted_networks(get_settings().trusted_proxy_cidrs)

    if not _is_trusted(peer_ip, trusted_networks):
        return str(peer_ip)

    forwarded = request.headers.get("x-forwarded-for", "")
    try:
        chain = [ipaddress.ip_address(value.strip()) for value in forwarded.split(",") if value.strip()]
    except ValueError:
        return str(peer_ip)
    if not chain:
        return str(peer_ip)

    # Walk from the trusted network edge towards the client. Ignore any
    # forwarded entries to the right of the first untrusted hop.
    candidate = peer_ip
    for address in reversed(chain):
        if not _is_trusted(candidate, trusted_networks):
            break
        candidate = address
    return str(candidate)


def rate_limit(bucket: str, maximum: int, window_seconds: int) -> Callable[[Request], None]:
    def enforce(request: Request) -> None:
        client_ip = _client_address(request)
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
