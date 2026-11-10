import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import spamhaus_drop
from packages.security_core.models import Base, ThreatFeedSnapshot


def _feed(ip_version: int, network: str, updated_at: datetime) -> bytes:
    records = [
        {"cidr": network, "sblid": "SBL12345"},
        {
            "timestamp": int(updated_at.timestamp()),
            "copyright": "Copyright Spamhaus Project",
        },
    ]
    return "\n".join(json.dumps(record) for record in records).encode()


def test_parse_drop_feed_checks_version_freshness_and_attribution():
    now = datetime.now(UTC)
    parsed = spamhaus_drop.parse_drop_feed(_feed(4, "8.8.8.0/24", now), 4, now)
    assert parsed.networks == ({"cidr": "8.8.8.0/24", "sblid": "SBL12345"},)
    assert parsed.expires_at == parsed.source_updated_at + timedelta(hours=26)

    with pytest.raises(ValueError, match="feed_invalid_network_record"):
        spamhaus_drop.parse_drop_feed(_feed(4, "10.0.0.0/8", now), 4, now)
    with pytest.raises(ValueError, match="feed_invalid_network_record"):
        spamhaus_drop.parse_drop_feed(_feed(4, "8.8.8.0/24", now), 6, now)
    with pytest.raises(ValueError, match="feed_stale_or_future"):
        spamhaus_drop.parse_drop_feed(
            _feed(4, "8.8.8.0/24", now - timedelta(hours=27)), 4, now,
        )


def test_feed_match_requires_public_ip_and_unexpired_snapshot():
    now = datetime.now(UTC)
    payload = json.dumps({"networks": [{"cidr": "8.8.8.0/24", "sblid": "SBL12345"}]})
    expires_at = now + timedelta(hours=1)
    assert spamhaus_drop.find_drop_match("8.8.8.8", payload, expires_at, now) == {
        "cidr": "8.8.8.0/24", "sblid": "SBL12345",
    }
    assert spamhaus_drop.find_drop_match("10.0.0.1", payload, expires_at, now) is None
    assert spamhaus_drop.find_drop_match(
        "8.8.8.8", payload, now - timedelta(seconds=1), now,
    ) is None


def test_sync_refreshes_both_feeds_once_and_respects_hourly_limit(monkeypatch):
    now = datetime.now(UTC)
    calls = []
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def fake_fetch(url: str) -> bytes:
        calls.append(url)
        version, network = (4, "8.8.8.0/24") if "drop_v4" in url else (6, "2001:4860::/32")
        return _feed(version, network, now)

    monkeypatch.setattr(spamhaus_drop, "_fetch", fake_fetch)
    assert spamhaus_drop.sync_spamhaus_drop_once(factory, now) is True
    assert len(calls) == 2
    assert spamhaus_drop.sync_spamhaus_drop_once(factory, now + timedelta(minutes=30)) is False
    assert len(calls) == 2
    with factory() as session:
        snapshot = session.get(ThreatFeedSnapshot, spamhaus_drop.FEED_ID)
    assert snapshot is not None
    assert snapshot.entry_count == 2
    engine.dispose()

