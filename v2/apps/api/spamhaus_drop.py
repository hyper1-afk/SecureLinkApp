from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from packages.security_core.models import ThreatFeedSnapshot, ThreatFeedSyncState

FEED_ID = "spamhaus_drop"
FEED_URLS = (
    ("https://www.spamhaus.org/drop/drop_v4.json", 4),
    ("https://www.spamhaus.org/drop/drop_v6.json", 6),
)
FEED_SOURCE_URL = "https://www.spamhaus.org/drop/"
MAX_FEED_BYTES = 2_000_000
MAX_FEED_ENTRIES = 10_000
MAX_DOWNLOAD_INTERVAL = timedelta(hours=1)
REFRESH_INTERVAL = timedelta(hours=24)
MAX_FEED_AGE = timedelta(hours=26)
SYNC_POLL_SECONDS = 3600
SBL_REFERENCE = re.compile(r"^SBL[0-9]+$", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedDropFeed:
    networks: tuple[dict[str, str], ...]
    source_updated_at: datetime
    expires_at: datetime
    copyright_text: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _json_records(content: bytes) -> list[dict[str, Any]]:
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("feed_not_utf8") from exc
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        records = []
        for line in decoded.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError("feed_invalid_json") from exc
        data = records
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data or any(not isinstance(row, dict) for row in data):
        raise ValueError("feed_invalid_shape")
    return data


def parse_drop_feed(content: bytes, ip_version: int, now: datetime) -> ParsedDropFeed:
    if len(content) > MAX_FEED_BYTES:
        raise ValueError("feed_too_large")
    if ip_version not in {4, 6}:
        raise ValueError("feed_invalid_ip_version")

    records = _json_records(content)
    networks: dict[str, str] = {}
    source_timestamp: int | None = None
    copyright_text: str | None = None
    for record in records:
        if "cidr" in record:
            try:
                network = ipaddress.ip_network(record["cidr"], strict=True)
            except (TypeError, ValueError) as exc:
                raise ValueError("feed_invalid_network") from exc
            reference = record.get("sblid")
            if (
                network.version != ip_version
                or not network.network_address.is_global
                or not network.broadcast_address.is_global
                or not isinstance(reference, str)
                or not SBL_REFERENCE.fullmatch(reference)
            ):
                raise ValueError("feed_invalid_network_record")
            networks[str(network)] = reference
        elif "timestamp" in record and "copyright" in record:
            timestamp = record["timestamp"]
            copyright_value = record["copyright"]
            if type(timestamp) is not int or not isinstance(copyright_value, str):
                raise ValueError("feed_invalid_metadata")
            source_timestamp = timestamp if source_timestamp is None else min(source_timestamp, timestamp)
            if "spamhaus" not in copyright_value.casefold():
                raise ValueError("feed_invalid_attribution")
            copyright_text = copyright_value
        else:
            raise ValueError("feed_unknown_record")

    if not networks or len(networks) > MAX_FEED_ENTRIES or source_timestamp is None or not copyright_text:
        raise ValueError("feed_incomplete")
    source_updated_at = datetime.fromtimestamp(source_timestamp, UTC)
    expires_at = source_updated_at + MAX_FEED_AGE
    if expires_at <= now or source_updated_at > now + timedelta(hours=1):
        raise ValueError("feed_stale_or_future")
    return ParsedDropFeed(
        networks=tuple(
            {"cidr": cidr, "sblid": networks[cidr]}
            for cidr in sorted(networks, key=lambda value: ipaddress.ip_network(value).prefixlen, reverse=True)
        ),
        source_updated_at=source_updated_at,
        expires_at=expires_at,
        copyright_text=copyright_text,
    )


def find_drop_match(
    ip_text: str,
    payload: str,
    expires_at: datetime,
    now: datetime,
) -> dict[str, str] | None:
    if expires_at <= now:
        return None
    try:
        address = ipaddress.ip_address(ip_text)
        indicators = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(indicators, dict):
        indicators = indicators.get("networks")
    if not address.is_global or not isinstance(indicators, list):
        return None
    for indicator in indicators:
        try:
            network = ipaddress.ip_network(indicator["cidr"], strict=True)
        except (KeyError, TypeError, ValueError):
            continue
        if address.version == network.version and address in network:
            return {"cidr": str(network), "sblid": str(indicator.get("sblid", ""))}
    return None


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SecureLink-V2-ThreatFeed/1.0", "Accept": "application/json"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    with opener.open(request, timeout=20) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("feed_http_response_invalid")
        content_type = response.headers.get_content_type()
        if content_type not in {"application/json", "text/json", "text/plain"}:
            raise ValueError("feed_content_type_invalid")
        content = response.read(MAX_FEED_BYTES + 1)
    if len(content) > MAX_FEED_BYTES:
        raise ValueError("feed_too_large")
    return content


def _last_attempt(state: ThreatFeedSyncState | None) -> datetime | None:
    if state is None or state.last_attempt_at is None:
        return None
    value = state.last_attempt_at
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def get_feed_session_factory() -> sessionmaker[Session]:
    database_url = os.environ.get("DATABASE_URL", "")
    try:
        database = make_url(database_url)
    except (ValueError, ImportError) as exc:
        raise RuntimeError("Threat feed worker requires a valid DATABASE_URL") from exc
    if (
        not database.drivername.startswith("postgresql")
        or not database.host
        or not database.username
        or not database.password
    ):
        raise RuntimeError("Threat feed worker requires authenticated PostgreSQL")
    if os.environ.get("APP_ENV") in {"staging", "production"} and (
        database.query.get("sslmode") != "verify-full"
        or not database.query.get("sslrootcert")
    ):
        raise RuntimeError("Threat feed worker requires verified PostgreSQL TLS")
    engine = create_engine(database_url, pool_pre_ping=True)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def sync_spamhaus_drop_once(
    session_factory: sessionmaker[Session] | None = None,
    now: datetime | None = None,
) -> bool:
    session_factory = session_factory or get_feed_session_factory()
    now = now or datetime.now(UTC)
    with session_factory() as session:
        state = session.get(ThreatFeedSyncState, FEED_ID)
        snapshot = session.get(ThreatFeedSnapshot, FEED_ID)
        last_attempt = _last_attempt(state)
        if last_attempt and now - last_attempt < MAX_DOWNLOAD_INTERVAL:
            return False
        snapshot_expires = (
            snapshot.expires_at.replace(tzinfo=UTC)
            if snapshot and snapshot.expires_at.tzinfo is None
            else snapshot.expires_at.astimezone(UTC) if snapshot else None
        )
        snapshot_fetched = (
            snapshot.fetched_at.replace(tzinfo=UTC)
            if snapshot and snapshot.fetched_at.tzinfo is None
            else snapshot.fetched_at.astimezone(UTC) if snapshot else None
        )
        if (
            snapshot
            and snapshot_expires
            and snapshot_fetched
            and snapshot_expires > now
            and now - snapshot_fetched < REFRESH_INTERVAL
        ):
            return True
        if state is None:
            state = ThreatFeedSyncState(feed_id=FEED_ID)
            session.add(state)
        state.last_attempt_at = now
        state.last_error = None
        session.commit()

    try:
        parsed = [parse_drop_feed(_fetch(url), version, now) for url, version in FEED_URLS]
        source_updated_at = min(item.source_updated_at for item in parsed)
        expires_at = min(item.expires_at for item in parsed)
        if expires_at <= now:
            raise ValueError("feed_stale_or_future")
        combined = {
            "source": "Spamhaus Project DROP",
            "source_url": FEED_SOURCE_URL,
            "copyright": sorted({item.copyright_text for item in parsed}),
            "networks": sorted(
                (entry for item in parsed for entry in item.networks),
                key=lambda entry: (entry["cidr"], entry["sblid"]),
            ),
        }
        if len(combined["networks"]) > MAX_FEED_ENTRIES:
            raise ValueError("feed_too_large")
        serialized = json.dumps(combined, sort_keys=True, separators=(",", ":"))
        snapshot = ThreatFeedSnapshot(
            feed_id=FEED_ID,
            payload=serialized,
            source_updated_at=source_updated_at,
            fetched_at=now,
            expires_at=expires_at,
            entry_count=len(combined["networks"]),
            content_hash=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError, ssl.SSLError):
        with session_factory() as session:
            state = session.get(ThreatFeedSyncState, FEED_ID)
            if state:
                state.last_error = "source_unavailable_or_invalid"
                session.commit()
        return False

    with session_factory() as session:
        session.merge(snapshot)
        state = session.get(ThreatFeedSyncState, FEED_ID)
        if state:
            state.last_error = None
        session.commit()
    return True


def main() -> None:
    session_factory = get_feed_session_factory()
    while True:
        sync_spamhaus_drop_once(session_factory)
        time.sleep(SYNC_POLL_SECONDS)


if __name__ == "__main__":
    main()

