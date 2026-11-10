import hashlib

from fastapi import Request

from apps.api import rate_limits
from apps.api.config import Settings


class RecordingRedis:
    def __init__(self):
        self.keys = []

    def eval(self, _script, _key_count, key, _window):
        self.keys.append(key)
        return [1, 60]

    def close(self):
        return None


def make_request(peer: str, forwarded: str = "", path: str = "/auth/login") -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "client": (peer, 12345),
            "headers": headers,
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


def key_for(client_ip: str) -> str:
    material = f"login:{client_ip}"
    digest = hashlib.sha256(material.encode()).hexdigest()
    return f"securelink:rate:v1:{digest}"


def test_untrusted_forwarded_header_cannot_change_rate_limit_identity(monkeypatch):
    redis = RecordingRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)
    monkeypatch.setattr(rate_limits, "get_settings", lambda: Settings())
    dependency = rate_limits.rate_limit("login", 10, 60)

    dependency(make_request("198.51.100.8", "203.0.113.9"))
    dependency(make_request("198.51.100.8", "192.0.2.44"))

    assert redis.keys == [key_for("198.51.100.8"), key_for("198.51.100.8")]


def test_trusted_proxy_chain_selects_first_untrusted_hop(monkeypatch):
    redis = RecordingRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)
    monkeypatch.setattr(
        rate_limits,
        "get_settings",
        lambda: Settings(trusted_proxy_cidrs="10.0.0.0/8"),
    )
    dependency = rate_limits.rate_limit("login", 10, 60)

    dependency(make_request("10.0.0.5", "203.0.113.9, 10.0.0.4"))

    assert redis.keys == [key_for("203.0.113.9")]


def test_malformed_forwarded_header_falls_back_to_trusted_peer(monkeypatch):
    redis = RecordingRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)
    monkeypatch.setattr(
        rate_limits,
        "get_settings",
        lambda: Settings(trusted_proxy_cidrs="10.0.0.0/8"),
    )
    dependency = rate_limits.rate_limit("login", 10, 60)

    dependency(make_request("10.0.0.5", "not-an-ip"))

    assert redis.keys == [key_for("10.0.0.5")]


def test_dynamic_route_parameters_do_not_create_new_redis_keys(monkeypatch):
    redis = RecordingRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)
    monkeypatch.setattr(rate_limits, "get_settings", lambda: Settings())
    dependency = rate_limits.rate_limit("url_scan", 20, 60)

    dependency(make_request("198.51.100.8", path="/organizations/org-one/scans"))
    dependency(make_request("198.51.100.8", path="/organizations/org-two/scans"))

    assert redis.keys == [redis.keys[0], redis.keys[0]]


def test_rate_limit_client_enforces_redis_tls_verification(monkeypatch):
    settings = Settings(redis_url="rediss://securelink:unique@redis.example.test:6379/0")
    monkeypatch.setattr(rate_limits, "get_settings", lambda: settings)
    observed = {}

    class FakeRedisClient:
        @staticmethod
        def from_url(url, **kwargs):
            observed["url"] = url
            observed.update(kwargs)
            return object()

    monkeypatch.setattr(rate_limits, "Redis", FakeRedisClient)

    rate_limits.get_rate_limit_client()

    assert observed["ssl_cert_reqs"] == "required"
    assert observed["ssl_check_hostname"] is True
