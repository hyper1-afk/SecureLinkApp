Warning: truncated output (original token count: 16891)
Total output lines: 1513

import base64
import hashlib
import json
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import (
    assets,
    auth,
    domain_monitor_worker,
    emailer,
    extension_auth,
    main,
    notification_worker,
    rate_limits,
    scanning,
)
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import (
    AuditEvent,
    Base,
    CaseApproval,
    CaseFinding,
    CaseSignal,
    DomainAsset,
    DomainMonitorState,
    EmailActionToken,
    ExtensionAuthorizationCode,
    ExtensionSession,
    Finding,
    IncidentCase,
    Membership,
    ScanEvidence,
    SecurityNotificationOutbox,
    SecuritySignal,
    ThreatFeedSnapshot,
    ThreatIndicator,
    UrlScan,
    User,
)
from packages.security_core.url_analysis import InvalidScanURL, analyze_url


class FakeRedis:
    def __init__(self):
        self.counts = {}

    def eval(self, _script, _key_count, key, _window):
        count = self.counts.get(key, 0) + 1
        self.counts[key] = count
        return [count, 60]

    def close(self):
        return None


@pytest.fixture
def client(monkeypatch) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    settings = Settings(
        app_secret_key="scan-test-secret-with-more-than-32-bytes",
        smtp_host="mail.example.test",
        smtp_from_email="no-reply@example.test",
        email_outbox_encryption_key=Fernet.generate_key().decode("ascii"),
        extension_redirect_uris=(
            "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/"
        ),
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(extension_auth, "get_settings", lambda: settings)
    monkeypatch.setattr(emailer, "get_settings", lambda: settings)
    monkeypatch.setattr(auth, "email_delivery_configured", lambda: True)
    redis = FakeRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)

    def override_session():
        with factory() as session:
            yield session

    main.app.state.test_session_factory = factory
    main.app.dependency_overrides[get_session] = override_session
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.dependency_overrides.clear()
    if hasattr(main.app.state, "test_session_factory"):
        del main.app.state.test_session_factory
    engine.dispose()


def register(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "a-long-scan-test-password",
            "organization_name": "Scan Test Org",
        },
    )
    assert response.status_code == 202
    with client.app.state.test_session_factory() as session:
        action = session.scalar(
            select(EmailActionToken)
            .join(User, User.id == EmailActionToken.user_id)
            .where(User.email_normalized == email.casefold(), EmailActionToken.purpose == "verify_email")
        )
        verify_token = emailer.decrypt_action_token(action.delivery_ciphertext)
    assert client.post("/auth/verify-email", json={"token": verify_token}).status_code == 200
    login = client.post(
        "/auth/login",
        json={"email": email, "password": "a-long-scan-test-password"},
    )
    assert login.status_code == 200
    return login.json()


def test_passive_url_analysis_redacts_sensitive_parts():
    result = analyze_url(
        "https://alice:secret@example.com/private/path?access_token=topsecret&next=https%3A%2F%2Fx.test#fragment"
    )
    assert result.display_url == "https://example.com/[path and query omitted]"
    assert result.hostname == "example.com"
    assert result.evidence["network_requests_made"] is False
    assert result.evidence["credentials_present"] is True
    assert result.evidence["sensitive_query_present"] is True
    assert result.evidence["redirect_parameter_present"] is True
    evidence_values = json.dumps(list(result.evidence.values()))
    assert all(
        secret not in evidence_values and secret not in result.display_url
        for secret in ("alice", "secret", "topsecret", "private/path", "fragment")
    )
    assert {finding.detector_code for finding in result.findings} >= {
        "credentials_in_url",
        "sensitive_query_parameter",
        "redirect_parameter",
    }


def test_passive_url_analysis_detects_sensitive_query_key_variants():
    result = analyze_url(
        "https://example.test/?api_key=hidden&clientSecret=hidden&apiKey=hidden&email=hidden"
    )
    assert result.evidence["sensitive_query_present"] is True
    assert any(finding.detector_code == "sensitive_query_parameter" for finding in result.findings)


def test_current_spamhaus_drop_match_is_audited_and_opens_review_case(client: TestClient):
    owner = register(client, "drop-feed-match@example.test")
    now = datetime.now(UTC)
    payload = json.dumps({
        "source": "Spamhaus Project DROP",
        "source_url": "https://www.spamhaus.org/drop/",
        "copyright": "Spamhaus Project test fixture",
        "networks": [{"cidr": "8.8.8.0/24", "sblid": "SBL12345"}],
    })
    with client.app.state.test_session_factory() as session:
        session.add(ThreatFeedSnapshot(
            feed_id="spamhaus_drop",
            payload=payload,
            source_updated_at=now - timedelta(minutes=5),
            fetched_at=now,
            expires_at=now + timedelta(hours=1),
            entry_count=1,
            content_hash=hashlib.sha256(payload.encode()).hexdigest(),
        ))
        session.commit()

    response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"url": "https://8.8.8.8/private?token=secret"},
    )
    assert response.status_code == 201
    assert "spamhaus_drop_network_match" in {
        item["detector_code"] for item in response.json()["findings"]
    }
    intelligence = response.json()["threat_intelligence"]
    assert intelligence["status"] == "current"
    assert intelligence["source"] == "Spamhaus Project DROP"
    assert intelligence["match"] == {"cidr": "8.8.8.0/24", "sblid": "SBL12345"}
    assert "content_hash" not in response.text and "networks" not in response.text
    assert "secret" not in response.text
    with client.app.state.test_session_factory() as session:
        evidence = session.scalar(select(ScanEvidence).where(ScanEvidence.scan_id == response.json()["id"]))
        evidence_data = json.loads(evidence.payload)
    assert evidence_data["threat_intelligence"]["match"] == {
        "cidr": "8.8.8.0/24", "sblid": "SBL12345",
    }
    assert evidence_data["threat_intelligence"]["source"] == "Spamhaus Project DROP"
    cases = client.get(
        f"/organizations/{owner['organization_id']}/cases",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    )
    assert cases.status_code == 200
    assert len(cases.json()) == 1
    history = client.get(
        f"/organizations/{owner['organization_id']}/scans",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    )
    assert history.status_code == 200
    assert history.json()[0]["threat_intelligence"] == intelligence


def test_expired_spamhaus_drop_snapshot_never_creates_a_match(client: TestClient):
    owner = register(client, "expired-drop-feed@example.test")
    now = datetime.now(UTC)
    payload = json.dumps({
        "source": "Spamhaus Project DROP",
        "networks": [{"cidr": "8.8.8.0/24", "sblid": "SBL12345"}],
    })
    with client.app.state.test_session_factory() as session:
        session.add(ThreatFeedSnapshot(
            feed_id="spamhaus_drop",
            payload=payload,
            source_updated_at=now - timedelta(hours=27),
            fetched_at=now - timedelta(hours=27),
            expires_at=now - timedelta(hours=1),
            entry_count=1,
            content_hash=hashlib.sha256(payload.encode()).hexdigest(),
        ))
        session.commit()

    response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"url": "https://8.8.8.8/"},
    )
    assert response.status_code == 201
    assert response.json()["findings"] == []
    assert response.json()["threat_intelligence"]["status"] == "unavailable"
    assert response.json()["threat_intelligence"]["match"] is None
    with client.app.state.test_session_factory() as session:
        evidence = session.scalar(select(ScanEvidence).where(ScanEvidence.scan_id == response.json()["id"]))
        evidence_data = json.loads(evidence.payload)
    assert evidence_data["threat_intelligence"]["status"] == "unavailable"


def test_scan_response_marks_a_previously_current_feed_stale_after_expiry():
    now = datetime.now(UTC)
    scan = SimpleNamespace(
        id="scan-id",
        status="completed",
        display_url="https://example.test/",
        hostname="example.test",
        scheme="https",
        created_at=now - timedelta(days=2),
    )
    evidence = SimpleNamespace(payload=json.dumps({
        "threat_intelligence": {
            "status": "current",
            "source_updated_at": (now - timedelta(days=2, hours=1)).isoformat(),
            "expires_at": (now - timedelta(hours=1)).isoformat(),
            "match": {"cidr": "8.8.8.0/24", "sblid": "SBL12345"},
        },
    }))

    response = scanning._response(scan, [], evidence)

    assert response.threat_intelligence is not None
    assert response.threat_intelligence.status == "stale"
    assert response.threat_intelligence.match == {"cidr": "8.8.8.0/24", "sblid": "SBL12345"}


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "https://example.test:bad/"])
def test_passive_url_analysis_rejects_non_http_or_invalid_urls(url: str):
    with pytest.raises(InvalidScanURL):
        analyze_url(url)


def test_scans_are_tenant_scoped_and_never_store_raw_url(client: TestClient):
    owner = register(client, "scan-owner@example.test")
    other = register(client, "scan-other@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    raw_url = "https://alice:secret@example.com/private/path?access_token=topsecret#fragment"
    response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers=headers,
        json={"url": raw_url},
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    scan = response.json()
    assert scan["display_url"] == "https://example.com/[path and query omitted]"
    assert "topsecret" not in response.text
    assert "private/path" not in response.text
    assert {item["detector_code"] for item in scan["findings"]} >= {
        "credentials_in_url",
        "sensitive_query_parameter",
    }

    with client.app.state.test_session_factory() as session:
        stored = session.get(UrlScan, scan["id"])
        evidence = session.scalar(select(ScanEvidence).where(ScanEvidence.scan_id == scan["id"]))
        findings = session.scalars(select(Finding).where(Finding.scan_id == scan["id"])).all()
        assert stored.display_url == "https://example.com/[path and query omitted]"
        assert raw_url not in evidence.payload
        assert "topsecret" not in evidence.payload
        assert len(findings) == len(scan["findings"])

    cross_tenant = client.get(
        f"/organizations/{owner['organization_id']}/scans/{scan['id']}",
        headers={"Authorization": f"Bearer {other['access_token']}"},
    )
    assert cross_tenant.status_code == 404
    signals = client.get(
        f"/organizations/{owner['organization_id']}/signals",
        headers=headers,
    )
    assert signals.status_code == 200
    assert len(signals.json()) == 1
    assert signals.json()[0]["source_type"] == "url_scan"
    assert signals.json()[0]["subject"] == "example.com"
    assert "topsecret" not in signals.text


def test_tenant_managed_hostname_indicators_are_audited_and_exact_match_only(client: TestClient):
    owner = register(client, "indicator-owner@example.test")
    other = register(client, "indicator-other@example.test")
    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    path = f"/organizations/{owner['organization_id']}/threat-indicators"

    created = client.post(path, headers=owner_headers, json={
        "hostname": "Bad.Example.com.", "note": "Customer supplied report",
    })
    assert created.status_code == 201
    assert created.json()["hostname"] == "bad.example.com"
    assert client.get(path, headers=other_headers).status_code == 404
    assert client.post(path, headers=owner_headers, json={"hostname": "https://bad.example.com/path"}).status_code == 422
    assert client.post(path, headers=owner_headers, json={"hostname": "bad.example.com"}).status_code == 409

    exact = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers=owner_headers,
        json={"url": "https://bad.example.com/login?email=private@example.com"},
    )
    subdomain = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers=owner_headers,
        json={"url": "https://sub.bad.example.com/"},
    )
    unrelated_tenant = client.post(
        f"/organizations/{other['organization_id']}/scans",
        headers=other_headers,
        json={"url": "https://bad.example.com/"},
    )
    assert exact.status_code == subdomain.status_code == unrelated_tenant.status_code == 201
    assert "tenant_threat_indicator_match" in {item["detector_code"] for item in exact.json()["findings"]}
    assert "tenant_threat_indicator_match" not in {item["detector_code"] for item in subdomain.json()["findings"]}
    assert "tenant_threat_indicator_match" not in {item["detector_code"] for item in unrelated_tenant.json()["findings"]}
    assert "private@example.com" not in exact.text

    with client.app.state.test_session_factory() as session:
        events = session.scalars(select(AuditEvent).where(
            AuditEvent.organization_id == owner["organization_id"],
            AuditEvent.action == "threat_indicator.created",
        )).all()
        assert len(events) == 1
        assert session.scalar(select(ThreatIndicator.hostname).where(
            ThreatIndicator.organization_id == owner["organization_id"],
        )) == "bad.example.com"


def test_viewers_cannot_start_scans(client: TestClient):
    owner = register(client, "scan-rbac-owner@example.test")
    viewer = register(client, "scan-rbac-viewer@example.test")
    with client.app.state.test_session_factory() as session:
        viewer_user = session.scalar(
            select(User).where(User.email_normalized == "scan-rbac-viewer@example.test")
        )
        session.add(
            Membership(
                organization_id=owner["organization_id"],
                user_id=viewer_user.id,
                role="viewer",
            )
        )
        session.commit()
    response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers={"Authorization": f"Bearer {viewer['access_token']}"},
        json={"url": "https://example.com"},
    )
    assert response.status_code == 403


def test_domain_assets_require_dns_ownership_and_are_tenant_scoped(client: TestClient, monkeypatch):
    owner = register(client, "asset-owner@example.test")
    other = register(client, "asset-other@example.test")
    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}

    created = client.post(
        f"/organizations/{owner['organization_id']}/assets/domains",
        headers=owner_headers,
        json={"hostname": "Example.COM."},
    )
    assert created.status_code == 201
    asset_data = created.json()
    assert asset_data["hostname"] == "example.com"
    assert asset_data["status"] == "pending"
    assert asset_data["dns_name"] == "_securelink-verification.example.com"
    challenge_value = asset_data["dns_value"]
    assert challenge_value.startswith("securelink-verification=")

    with client.app.state.test_session_factory() as session:
        asset = session.get(DomainAsset, asset_data["id"])
        assert asset.status == "pending"
        assert challenge_value not in asset.verification_token_hash

    assert client.get(
        f"/organizations/{owner['organization_id']}/assets/domains", headers=other_headers
    ).status_code == 404
    assert client.post(
        f"/organizations/{owner['organization_id']}/assets/domains/{asset_data['id']}/verify",
        headers=other_headers,
    ).status_code == 404
    assert client.post(
        f"/organizations/{owner['organization_id']}/assets/domains/{asset_data['id']}/challenge",
        headers=other_headers,
    ).status_code == 404
    assert client.delete(
        f"/organizations/{owner['organization_id']}/assets/domains/{asset_data['id']}",
        headers=other_headers,
    ).status_code == 404
    enable_url = (
        f"/organizations/{owner['organization_id']}/assets/domains/{asset_data['id']}/monitoring"
    )
    assert client.patch(enable_url, headers=owner_headers, json={"enabled": True}).status_code == 409
    assert client.patch(enable_url, headers=other_headers, json={"enabled": True}).status_code == 404

    class Resolver:
        timeout = None
        lifetime = None

        def resolve(self, qname, record_type):
            assert qname == "_securelink-verification.example.com"
            assert record_type == "TXT"
            return [SimpleNamespace(strings=[challenge_value.encode()])]

    monkeypatch.setattr(assets.dns.resolver, "Resolver", lambda configure=True: Resolver())
    verified = client.post(
        f"/organizations/{owner['organization_id']}/assets/domains/{asset_data['id']}/verify",
        headers=owner_headers,
    )
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    assert verified.json()["monitoring_enabled"] is False
    assert verified.json()["monitoring_state"] == "paused"
    assert verified.json()["dns_value"] is None

    enabled = client.patch(enable_url, headers=owner_headers, json={"enabled": True})
    assert enabled.status_code == 200
    assert enabled.json()["monitoring_enabled"] is True
    assert enabled.json()["monitoring_state"] == "pending"
    paused = client.patch(enable_url, headers=owner_headers, json={"enabled": False})
    assert paused.status_code == 200
    assert paused.json()["monitoring_enabled"] is False

    with client.app.state.test_session_factory() as session:
        asset = session.get(DomainAsset, asset_data["id"])
        audit = session.scalars(
            select(AuditEvent).where(AuditEvent.target_id == asset_data["id"])
        ).all()
        assert asset.status == "verified"
        assert asset.verification_token_hash is None
        assert {event.action for event in audit} == {
            "domain_asset.created", "domain_asset.verified",
            "domain_asset.monitoring_enabled", "domain_asset.monitoring_disabled",
        }


@pytest.mark.parametrize(
    ("hostname", "email"),
    [
        ("https://example.com", "invalid-domain-url@example.test"),
        ("example.com/path", "invalid-domain-path@example.test"),
        ("*.example.com", "invalid-domain-wildcard@example.test"),
        ("127.0.0.1", "invalid-domain-ip@example.test"),
        ("localhost", "invalid-domain-localhost@example.test"),
    ],
)
def test_domain_asset_rejects_non_domain_targets(client: TestClient, hostname: str, email: str):
    owner = register(client, email)
    response = client.post(
        f"/organizations/{owner['organization_id']}/assets/domains",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"hostname": hostname},
    )
    assert response.status_code == 422


def test_domain_asset_creation_is_admin_only(client: TestClient):
    owner = register(client, "asset-rbac-owner@example.test")
    viewer = register(client, "asset-rbac-viewer@example.test")
    analyst = register(client, "asset-rbac-analyst@example.test")
    with client.app.state.test_session_factory() as session:
        viewer_user = session.scalar(
            select(User).where(User.email_normalized == "asset-rbac-viewer@example.test")
        )
        analyst_user = session.scalar(
            select(User).where(User.email_normalized == "asset-rbac-analyst@example.test")
        )
        session.add(
            Membership(
                organization_id=owner["organization_id"],
                user_id=viewer_user.id,
                role="viewer",
            )
        )
        session.add(Membership(
            organization_id=owner["organization_id"], user_id=analyst_user.id, role="analyst",
        ))
        session.commit()
    path = f"/organizations/{owner['organization_id']}/assets/domains"
    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    asset = client.post(path, headers=owner_headers, json={"hostname": "rbac.example.com"})
    assert asset.status_code == 201
    for member in (viewer, analyst):
        headers = {"Authorization": f"Bearer {member['access_token']}"}
        assert client.get(path, headers=headers).status_code == 200
        response = client.post(
            path,
            headers=headers,
            json={"hostname": "denied.example.com"},
        )
        assert response.status_code == 403
        asset_id = asset.json()["id"]
        assert client.post(f"{path}/{asset_id}/challenge", headers=headers).status_code == 403
        assert client.post(f"{path}/{asset_id}/verify", headers=headers).status_code == 403
        assert client.patch(
            f"{path}/{asset_id}/monitoring", headers=headers, json={"enabled": True},
        ).status_code == 403
        assert client.delete(f"{path}/{asset_id}", headers=headers).status_code == 403


def test_domain_monitor_dns_checks_are_explicit_and_deduplicate_state_transitions(
    client: TestClient, monkeypatch,
):
    owner = register(client, "domain-monitor-owner@example.test")
    with client.app.state.test_session_factory() as session:
        user = session.scalar(select(User).where(User.email_normalized == "domain-monitor-owner@example.test"))
        asset = DomainAsset(
            organization_id=owner["organization_id"],
            hostname="mail.example.test",
            status="verified",
            monitoring_enabled=True,
            verified_at=datetime.now(UTC),
            created_by_user_id=user.id,
        )
        session.add(asset)
        session.flush()
        asset_id = asset.id
        session.add(DomainMonitorState(
            asset_id=asset.id,
            organization_id=owner["organization_id"],
            monitor_type="email_dns_security",
            current_state="{}",
            generation=0,
            next_check_at=datetime.now(UTC) - timedelta(seconds=1),
        ))
        session.commit()

    monkeypatch.setattr(
        domain_monitor_worker, "get_session_factory", lambda: client.app.state.test_session_factory,
    )

    def dns_timeout(_hostname, _resolver):
        raise assets.dns.exception.Timeout

    monkeypatch.setattr(domain_monitor_worker, "collect_issues", dns_timeout)
    assert domain_monitor_worker.process_one() is True
    org_url = f"/organizations/{owner['organization_id']}"
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    assert client.get(org_url + "/signals", headers=headers).json() == []
    monitor_asset = client.get(org_url + "/assets/domains", headers=headers).json()[0]
    assert monitor_asset["monitoring_state"] == "error"
    with client.app.state.test_session_factory() as session:
        state = session.get(
            DomainMonitorState,
            (asset_id, owner["organization_id"], "email_dns_security"),
        )
        state.next_check_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    monkeypatch.setattr(
        domain_monitor_worker,
        "collect_issues",
        lambda _hostname, _resolver: {
            "spf_policy": {
                "severity": "high",
                "title": "Multiple SPF records found",
                "summary": "Conflicting SPF records require review.",
            },
            "dmarc_policy": {
                "severity": "critical",
                "title": "Multiple DMARC records found",
                "summary": "Conflicting DMARC records require review.",
            },
        },
    )
    assert domain_monitor_worker.process_one() is True
    signals = client.get(org_url + "/signals", headers=headers).json()
    assert len(signals) == 2
    assert signals[0]["source_type"] == "domain_monitor"
    assert signals[0]["subject"] == "mail.example.test"
    monitor_asset = client.get(org_url + "/assets/domains", headers=headers).json()[0]
    assert monitor_asset["monitoring_state"] == "findings"
    assert monitor_asset["monitoring_finding_count"] == 2
    cases = client.get(org_url + "/cases", headers=headers).json()
    assert len(cases) == 1
    assert cases[0]["scan_id"] is None
    assert cases[0]["severity"] == "critical"
    assert {item["id"] for item in cases[0]["signals"]} == {item["id"] for item in signals}
    sent = []
    monkeypatch.setattr(
        notification_worker,
        "get_session_factory",
        lambda: client.app.state.test_session_factory,
    )
    monkeypatch.setattr(
        notification_worker,
        "send_high_priority_case_email",
        lambda *args: sent.append(args),
    )
    assert notification_worker.process_one() is True
    assert sent[0][3] == "mail.example.test"
    assert domain_monitor_worker.process_one() is False

    with client.app.state.test_session_factory() as session:
        state = session.get(
            DomainMonitorState,
            (asset_id, owner["organization_id"], "email_dns_security"),
        )
        state.next_check_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    monkeypatch.setattr(domain_monitor_worker, "collect_issues", lambda _hostname, _resolver: {})
    assert domain_monitor_worker.process_one() is True
    signals = client.get(org_url + "/signals", headers=headers).json()
    assert len(signals) == 4
    assert {item["signal_type"] for item in signals} >= {"spf_policy_resolved", "dmarc_policy_resolved"}
    monitor_asset = client.get(org_url + "/assets/domains", headers=headers).json()[0]
    assert monitor_asset["monitoring_state"] == "healthy"
    disabled = client.patch(
        f"{org_url}/assets/domains/{asset_id}/monitoring",
        headers=headers,
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["monitoring_state"] == "paused"
    assert domain_monitor_worker.process_one() is False


def test_domain_monitor_collector_checks_only_spf_and_dmarc_txt_records():
    class Resolver:
        def __init__(self, records):
            self.records = records
            self.queries = []

        def resolve(self, name, record_type):
            self.queries.append((name, record_type))
            values = self.records.get(name, [])
            return [SimpleNamespace(strings=[value.encode()]) for value in values]

    resolver = Resolver({
        "mail.example.com": ["v=spf1 include:mail.example.net -all"],
        "_dmarc.mail.example.com": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
    })
    issues = domain_monitor_worker.collect_issues("mail.example.com", resolver)
    assert set(issues) == {"dmarc_policy"}
    assert issues["dmarc_policy"]["severity"] == "low"
    assert resolver.queries == [
        ("mail.example.com", "TXT"),
        ("_dmarc.mail.example.com", "TXT"),
    ]
    empty = domain_monitor_worker.collect_issues("mail.example.com", Resolver({}))
    assert set(empty) == {"spf_policy", "dmarc_policy"}
    duplicate_spf = domain_monitor_worker.collect_issues(
        "mail.example.com",
        Resolver({
            "mail.example.com": ["v=spf1 -all", "v=spf1 ~all"],
            "_dmarc.mail.example.com": ["v=DMARC1; p=reject"],
        }),
    )
    assert duplicate_spf["spf_policy"]["severity"] == "high"
    assert "dmarc_policy" not in duplicate_spf
    malformed_prefix = domain_monitor_worker.collect_issues(
        "mail.example.com",
        Resolver({
            "mail.example.com": ["v=spf10 -all"],
            "_dmarc.mail.example.com": ["v=DMARC1invalid; p=reject"],
     …1891 tokens truncated…
    assert client.get(scan_url, headers=analyst_headers).status_code == 200
    assert client.get(case_url, headers=analyst_headers).status_code == 200
    assert client.patch(case_url + "/status", headers=analyst_headers, json={"status": "investigating"}).status_code == 200
    assert client.post(
        case_url + "/notes", headers=analyst_headers, json={"content": "Reviewed evidence."},
    ).status_code == 201

    assert client.get(scan_url, headers=viewer_headers).status_code == 200
    assert client.get(case_url, headers=viewer_headers).status_code == 200
    assert client.get(organization_url + "/scans", headers=viewer_headers).status_code == 200
    assert client.get(organization_url + "/cases", headers=viewer_headers).status_code == 200
    assert client.post(
        f"{organization_url}/scans", headers=viewer_headers, json={"url": "https://example.com"},
    ).status_code == 403
    assert client.post(
        f"{organization_url}/cases/from-scan/{scan_id}", headers=viewer_headers,
    ).status_code == 403
    assert client.patch(
        case_url + "/status", headers=viewer_headers, json={"status": "resolved"},
    ).status_code == 403
    assert client.post(
        case_url + "/notes", headers=viewer_headers, json={"content": "Not permitted."},
    ).status_code == 403

    assert client.get(case_url, headers=other_headers).status_code == 404
    assert client.get(scan_url, headers=other_headers).status_code == 404
    assert client.get(organization_url + "/signals", headers=other_headers).status_code == 404


def test_case_approval_requires_separate_owner_review_and_never_executes_action(client: TestClient):
    owner = register(client, "approval-owner@example.test")
    analyst = register(client, "approval-analyst@example.test")
    org_url = f"/organizations/{owner['organization_id']}"
    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    analyst_headers = {"Authorization": f"Bearer {analyst['access_token']}"}
    with client.app.state.test_session_factory() as session:
        analyst_user = session.scalar(select(User).where(User.email_normalized == "approval-analyst@example.test"))
        assert analyst_user is not None
        session.add(Membership(organization_id=owner["organization_id"], user_id=analyst_user.id, role="analyst"))
        session.commit()

    scan = client.post(
        org_url + "/scans",
        headers=owner_headers,
        json={"url": "https://alice:secret@example.com/private?token=private"},
    )
    assert scan.status_code == 201
    case = client.get(org_url + "/cases", headers=owner_headers).json()[0]
    case_url = org_url + f"/cases/{case['id']}"
    assert client.patch(case_url + "/status", headers=analyst_headers, json={"status": "investigating"}).status_code == 200
    request = client.post(
        case_url + "/approvals",
        headers=analyst_headers,
        json={"action": "revoke_extension_sessions", "rationale": "Contain suspected account compromise."},
    )
    assert request.status_code == 201
    approval = request.json()
    assert approval["status"] == "pending"
    assert client.get(case_url, headers=owner_headers).json()["status"] == "awaiting_approval"
    assert client.post(
        case_url + f"/approvals/{approval['id']}/decision",
        headers=analyst_headers,
        json={"decision": "approved", "note": "Analyst cannot review this."},
    ).status_code == 403
    assert client.post(
        case_url + f"/approvals/{approval['id']}/decision",
        headers=owner_headers,
        json={"decision": "approved", "note": "   "},
    ).status_code == 422
    decision = client.post(
        case_url + f"/approvals/{approval['id']}/decision",
        headers=owner_headers,
        json={"decision": "approved", "note": "Reviewed incident evidence."},
    )
    assert decision.status_code == 200
    assert decision.json()["status"] == "approved"
    assert client.get(case_url, headers=owner_headers).json()["status"] == "investigating"
    assert client.get(case_url + "/approvals", headers=owner_headers).json()[0]["id"] == approval["id"]
    with client.app.state.test_session_factory() as session:
        stored = session.get(CaseApproval, approval["id"])
        assert stored is not None and stored.reviewer_user_id != stored.requester_user_id
        assert session.scalar(select(AuditEvent).where(
            AuditEvent.action == "case.approval_approved", AuditEvent.target_id == approval["id"],
        )) is not None

    expiring = client.post(
        case_url + "/approvals",
        headers=analyst_headers,
        json={"action": "disable_domain_monitoring", "rationale": "Review monitoring scope."},
    )
    assert expiring.status_code == 201
    expiring_id = expiring.json()["id"]
    with client.app.state.test_session_factory() as session:
        stored = session.get(CaseApproval, expiring_id)
        assert stored is not None
        stored.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        session.commit()
    history = client.get(case_url + "/approvals", headers=owner_headers)
    assert history.status_code == 200
    assert next(item for item in history.json() if item["id"] == expiring_id)["status"] == "expired"
    assert client.get(case_url, headers=owner_headers).json()["status"] == "investigating"
    with client.app.state.test_session_factory() as session:
        expiry_audit = session.scalar(select(AuditEvent).where(
            AuditEvent.action == "case.approval_expired", AuditEvent.target_id == expiring_id,
        ))
        assert expiry_audit is not None and expiry_audit.actor_type == "system"

    owner_request = client.post(
        case_url + "/approvals",
        headers=owner_headers,
        json={"action": "disable_threat_indicator", "rationale": "Test requester reviewer separation."},
    )
    assert owner_request.status_code == 201
    assert client.post(
        case_url + f"/approvals/{owner_request.json()['id']}/decision",
        headers=owner_headers,
        json={"decision": "approved", "note": "I cannot approve my own request."},
    ).status_code == 403


def test_generic_monitor_signal_can_open_a_tenant_scoped_case(client: TestClient):
    owner = register(client, "monitor-signal-owner@example.test")
    other = register(client, "monitor-signal-other@example.test")
    with client.app.state.test_session_factory() as session:
        signal = SecuritySignal(
            organization_id=owner["organization_id"],
            source_type="domain_monitor",
            source_reference="dns-check-0001",
            signal_type="dmarc_policy",
            subject="example.test",
            severity="high",
            title="DMARC policy is missing",
            summary="A verified domain has no DMARC record at the time of this check.",
            observed_at=datetime.now(UTC),
            payload='{"record_type":"DMARC","present":false}',
            content_hash=hashlib.sha256(b'{"record_type":"DMARC","present":false}').hexdigest(),
        )
        related_signal = SecuritySignal(
            organization_id=owner["organization_id"],
            source_type="domain_monitor",
            source_reference="dns-check-0002",
            signal_type="tls_expiry",
            subject="example.test",
            severity="critical",
            title="TLS certificate has expired",
            summary="The verified domain endpoint returned an expired certificate.",
            observed_at=datetime.now(UTC),
            payload='{"certificate_expired":true}',
            content_hash=hashlib.sha256(b'{"certificate_expired":true}').hexdigest(),
        )
        session.add_all([signal, related_signal])
        session.commit()
        signal_id = signal.id
        related_signal_id = related_signal.id

    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    org_url = f"/organizations/{owner['organization_id']}"
    listed = client.get(org_url + "/signals", headers=owner_headers)
    assert listed.status_code == 200
    assert {item["id"] for item in listed.json()} == {signal_id, related_signal_id}
    assert client.get(org_url + "/signals", headers=other_headers).status_code == 404

    opened = client.post(org_url + f"/cases/from-signal/{signal_id}", headers=owner_headers)
    assert opened.status_code == 201
    case = opened.json()
    assert case["scan_id"] is None
    assert case["hostname"] == "example.test"
    assert case["signals"][0]["id"] == signal_id
    assert case["findings"] == []
    note_response = client.post(
        org_url + f"/cases/{case['id']}/notes",
        headers=owner_headers,
        json={"content": "Reviewed DNS evidence; confirm with the customer."},
    )
    assert note_response.status_code == 201
    assert note_response.json()["notes"][0]["content"] == "Reviewed DNS evidence; confirm with the customer."
    with client.app.state.test_session_factory() as session:
        note_audit = session.scalar(select(AuditEvent).where(
            AuditEvent.action == "case.note_added",
            AuditEvent.target_id == case["id"],
        ))
        assert note_audit is not None
        assert note_response.json()["notes"][0]["id"] in note_audit.details
        assert "confirm with the customer" not in note_audit.details
    assert client.post(
        org_url + f"/cases/{case['id']}/notes",
        headers=owner_headers,
        json={"content": "   "},
    ).status_code == 422
    assert client.post(
        f"/organizations/{other['organization_id']}/cases/{case['id']}/notes",
        headers=other_headers,
        json={"content": "cross-tenant"},
    ).status_code == 404
    linked = client.post(
        org_url + f"/cases/{case['id']}/signals/{related_signal_id}", headers=owner_headers,
    )
    assert linked.status_code == 200
    assert linked.json()["severity"] == "critical"
    assert {item["id"] for item in linked.json()["signals"]} == {signal_id, related_signal_id}
    assert client.post(
        org_url + f"/cases/{case['id']}/signals/{related_signal_id}", headers=owner_headers,
    ).status_code == 200
    assert client.post(
        f"/organizations/{other['organization_id']}/cases/{case['id']}/signals/{related_signal_id}",
        headers=other_headers,
    ).status_code == 404
    assert client.get(org_url + f"/cases/{case['id']}", headers=owner_headers).status_code == 200
    assert client.get(org_url + f"/cases/{case['id']}", headers=other_headers).status_code == 404
    duplicate = client.post(org_url + f"/cases/from-signal/{signal_id}", headers=owner_headers)
    assert duplicate.status_code == 200
    assert duplicate.json()["id"] == case["id"]


def test_priority_notification_worker_sends_hostname_only(client: TestClient, monkeypatch):
    owner = register(client, "alert-worker@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers=headers,
        json={"url": "https://alice:secret@example.com/private?token=private"},
    )
    assert response.status_code == 201
    sent = []
    monkeypatch.setattr(notification_worker, "get_session_factory", lambda: client.app.state.test_session_factory)
    monkeypatch.setattr(notification_worker, "send_high_priority_case_email", lambda *args: sent.append(args))
    assert notification_worker.process_one() is True
    assert len(sent) == 1
    assert sent[0][2:] == ("high", "example.com", client.get(
        f"/organizations/{owner['organization_id']}/cases",
        headers=headers,
    ).json()[0]["id"])
    assert "secret" not in repr(sent)
    assert notification_worker.process_one() is False
    status = client.get(
        f"/organizations/{owner['organization_id']}/notification-status", headers=headers
    )
    assert status.json() == {"pending_count": 0, "failed_count": 0, "oldest_pending_at": None}


def test_repeated_high_priority_scans_update_one_active_case_without_duplicate_email(client: TestClient):
    owner = register(client, "deduplicated-alert@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    scans = f"/organizations/{owner['organization_id']}/scans"
    for _ in range(2):
        response = client.post(scans, headers=headers, json={"url": "https://alice:secret@example.com/private"})
        assert response.status_code == 201

    cases = client.get(f"/organizations/{owner['organization_id']}/cases", headers=headers)
    assert cases.status_code == 200
    assert len(cases.json()) == 1
    case = cases.json()[0]
    assert len(case["signals"]) == 2
    assert len(case["findings"]) == 2
    delivery = client.get(
        f"/organizations/{owner['organization_id']}/notification-status", headers=headers,
    )
    assert delivery.status_code == 200
    assert delivery.json()["pending_count"] == 1
    with client.app.state.test_session_factory() as session:
        actions = session.scalars(select(AuditEvent.action).where(
            AuditEvent.organization_id == owner["organization_id"],
            AuditEvent.action.in_(("case.auto_created_from_scan", "case.auto_updated_from_scan")),
        )).all()
        assert actions.count("case.auto_created_from_scan") == 1
        assert actions.count("case.auto_updated_from_scan") == 1


def test_clean_scan_cannot_open_empty_case(client: TestClient):
    owner = register(client, "case-empty-scan@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    scan_response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers=headers,
        json={"url": "https://example.com/"},
    )
    assert scan_response.status_code == 201
    assert scan_response.json()["findings"] == []
    response = client.post(
        f"/organizations/{owner['organization_id']}/cases/from-scan/{scan_response.json()['id']}",
        headers=headers,
    )
    assert response.status_code == 409


def test_priority_email_preference_is_member_scoped_and_audited(client: TestClient):
    owner = register(client, "alerts-owner@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    path = f"/organizations/{owner['organization_id']}/notification-preferences"
    assert client.get(path, headers=headers).json() == {"priority_email_enabled": True}
    response = client.patch(path, headers=headers, json={"priority_email_enabled": False})
    assert response.status_code == 200
    assert response.json() == {"priority_email_enabled": False}
    other = register(client, "alerts-other@example.test")
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    assert client.get(path, headers=other_headers).status_code == 404
    assert client.patch(path, headers=other_headers, json={"priority_email_enabled": True}).status_code == 404
    with client.app.state.test_session_factory() as session:
        event = session.scalar(select(AuditEvent).where(
            AuditEvent.action == "notification.priority_email_preference_changed"
        ))
        assert event is not None
        assert json.loads(event.details) == {"enabled": False}


def test_dashboard_page_uses_private_headers_and_discloses_scan_limits(client: TestClient):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "does not fetch the page" in response.text
    assert "not a safety verdict" in response.text
    assert "Authorized domains" in response.text
    assert "Cases" in response.text
    assert "Browser extension sessions" in response.text


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _authorize_extension(client: TestClient, owner: dict[str, str], verifier: str) -> str:
    response = client.post(
        "/extension/oauth/authorize",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={
            "client_id": "securelink-chrome-extension",
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "organization_id": owner["organization_id"],
            "state": "s" * 43,
            "code_challenge": _challenge(verifier),
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    callback = parse_qs(urlsplit(response.json()["redirect_url"]).query)
    assert callback["state"] == ["s" * 43]
    return callback["code"][0]


def test_extension_oauth_pkce_session_is_scoped_short_lived_and_revocable(
    client: TestClient,
):
    owner = register(client, "extension-oauth@example.test")
    assert client.post(
        "/extension/v1/scans",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"url": "https://example.test"},
    ).status_code == 401
    authorizable = client.get(
        "/extension/oauth/organizations",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    )
    assert authorizable.status_code == 200
    assert authorizable.headers["cache-control"] == "no-store"
    assert authorizable.json()["organizations"][0]["id"] == owner["organization_id"]
    verifier = "v" * 43
    code = _authorize_extension(client, owner, verifier)
    exchange = client.post(
        "/extension/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "securelink-chrome-extension",
            "code": code,
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "code_verifier": verifier,
        },
    )
    assert exchange.status_code == 200
    assert exchange.headers["cache-control"] == "no-store"
    token = exchange.json()["access_token"]
    assert exchange.json()["scope"] == "url_scan"
    assert exchange.json()["expires_in"] == 12 * 60 * 60
    assert "refresh_token" not in exchange.json()
    with client.app.state.test_session_factory() as session:
        stored = session.scalar(select(ExtensionSession))
        auth_code = session.scalar(select(ExtensionAuthorizationCode))
        assert stored.token_hash != token
        assert auth_code.consumed_at is not None

    extension_headers = {"Authorization": f"Bearer {token}"}
    current_session = client.get("/extension/oauth/session", headers=extension_headers)
    assert current_session.status_code == 200
    assert current_session.headers["cache-control"] == "no-store"
    assert current_session.json()["organization_id"] == owner["organization_id"]
    scan = client.post(
        "/extension/v1/scans",
        headers=extension_headers,
        json={
            "url": "https://example.test/path?session=%5BREDACTED%5D",
            "redactions": {
                "credentials_removed": True,
                "fragment_removed": True,
                "sensitive_query_values_removed": 1,
            },
        },
    )
    assert scan.status_code == 201
    assert scan.json()["display_url"] == "https://example.test/[path and query omitted]"
    assert "private" not in scan.text
    with client.app.state.test_session_factory() as session:
        evidence = session.scalar(select(ScanEvidence).where(ScanEvidence.scan_id == scan.json()["id"]))
        assert evidence is not None
        evidence_document = json.loads(evidence.payload)
        assert evidence_document["client_reported_redactions"] == {
            "credentials_removed": True,
            "fragment_removed": True,
            "sensitive_query_values_removed": 1,
        }
        assert "[REDACTED]" not in evidence.payload
        assert "private" not in evidence.payload
    invalid_redactions = client.post(
        "/extension/v1/scans",
        headers=extension_headers,
        json={
            "url": "https://example.test/path",
            "redactions": {"sensitive_query_values_removed": 65},
        },
    )
    assert invalid_redactions.status_code == 422
    assert client.get(
        f"/organizations/{owner['organization_id']}/signals",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    ).json()[0]["source_type"] == "extension_scan"
    assert client.get(
        f"/organizations/{owner['organization_id']}/scans",
        headers=extension_headers,
    ).status_code == 401
    assert client.post(
        "/extension/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "securelink-chrome-extension",
            "code": code,
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "code_verifier": verifier,
        },
    ).status_code == 400
    assert client.post("/extension/oauth/revoke", headers=extension_headers).status_code == 204
    assert client.get("/extension/oauth/session", headers=extension_headers).status_code == 401
    assert client.post(
        "/extension/v1/scans",
        headers=extension_headers,
        json={"url": "https://example.test"},
    ).status_code == 401


def test_expired_privileged_mfa_grace_blocks_existing_extension_session(client: TestClient):
    owner = register(client, "extension-mfa@example.test")
    verifier = "m" * 43
    code = _authorize_extension(client, owner, verifier)
    exchange = client.post(
        "/extension/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "securelink-chrome-extension",
            "code": code,
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "code_verifier": verifier,
        },
    )
    assert exchange.status_code == 200
    extension_headers = {"Authorization": f"Bearer {exchange.json()['access_token']}"}

    with client.app.state.test_session_factory() as session:
        user = session.scalar(select(User).where(User.email_normalized == "extension-mfa@example.test"))
        user.privileged_mfa_grace_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    assert client.get("/extension/oauth/organizations", headers={
        "Authorization": f"Bearer {owner['access_token']}"
    }).json()["organizations"] == []
    assert client.get("/extension/oauth/session", headers=extension_headers).status_code == 403
    sessions = client.get(
        "/extension/oauth/sessions",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    )
    assert sessions.status_code == 200
    assert sessions.json()[0]["status"] == "invalidated"
    assert client.post(
        "/extension/v1/scans", headers=extension_headers, json={"url": "https://example.com"}
    ).status_code == 403


def test_extension_oauth_rejects_unregistered_redirect_and_bad_pkce(client: TestClient):
    owner = register(client, "extension-invalid-oauth@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    for redirect_uri in (
        "https://attacker.example.test/callback",
        "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/",
    ):
        payload = {
            "client_id": "securelink-chrome-extension",
            "redirect_uri": redirect_uri,
            "organization_id": owner["organization_id"],
            "state": "s" * 43,
            "code_challenge": _challenge("v" * 43),
            "code_challenge_method": "S256",
        }
        response = client.post("/extension/oauth/authorize", headers=headers, json=payload)
        assert response.status_code == 400

    code = _authorize_extension(client, owner, "v" * 43)
    invalid_exchange = client.post(
        "/extension/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "securelink-chrome-extension",
            "code": code,
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "code_verifier": "x" * 43,
        },
    )
    assert invalid_exchange.status_code == 400
    with client.app.state.test_session_factory() as session:
        auth_code = session.scalar(select(ExtensionAuthorizationCode))
        assert auth_code.consumed_at is not None


def test_viewer_cannot_authorize_extension_scanning(client: TestClient):
    viewer = register(client, "extension-viewer@example.test")
    with client.app.state.test_session_factory() as session:
        membership = session.scalar(
            select(Membership).where(Membership.organization_id == viewer["organization_id"])
        )
        membership.role = "viewer"
        session.commit()

    headers = {"Authorization": f"Bearer {viewer['access_token']}"}
    assert client.get("/extension/oauth/organizations", headers=headers).json() == {
        "organizations": []
    }
    response = client.post(
        "/extension/oauth/authorize",
        headers=headers,
        json={
            "client_id": "securelink-chrome-extension",
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "organization_id": viewer["organization_id"],
            "state": "s" * 43,
            "code_challenge": _challenge("v" * 43),
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 403


def test_password_reset_token_version_invalidates_extension_session(client: TestClient):
    owner = register(client, "extension-revoked-by-reset@example.test")
    verifier = "v" * 43
    code = _authorize_extension(client, owner, verifier)
    response = client.post(
        "/extension/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "securelink-chrome-extension",
            "code": code,
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    with client.app.state.test_session_factory() as session:
        user = session.scalar(select(User).where(User.email_normalized == "extension-revoked-by-reset@example.test"))
        user.token_version += 1
        session.commit()

    relogin = client.post(
        "/auth/login",
        json={"email": "extension-revoked-by-reset@example.test", "password": "a-long-scan-test-password"},
    )
    assert relogin.status_code == 200
    sessions = client.get(
        "/extension/oauth/sessions",
        headers={"Authorization": f"Bearer {relogin.json()['access_token']}"},
    )
    assert sessions.json()[0]["status"] == "invalidated"

    assert client.post(
        "/extension/v1/scans",
        headers=headers,
        json={"url": "https://example.test"},
    ).status_code == 401


def test_extension_sessions_can_be_revoked_only_by_the_owning_account(client: TestClient):
    owner = register(client, "extension-session-owner@example.test")
    other = register(client, "extension-session-other@example.test")
    verifier = "v" * 43
    code = _authorize_extension(client, owner, verifier)
    exchange = client.post(
        "/extension/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": "securelink-chrome-extension",
            "code": code,
            "redirect_uri": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
            "code_verifier": verifier,
        },
    )
    assert exchange.status_code == 200
    extension_token = exchange.json()["access_token"]
    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}

    sessions = client.get("/extension/oauth/sessions", headers=owner_headers)
    assert sessions.status_code == 200
    assert sessions.headers["cache-control"] == "no-store"
    assert len(sessions.json()) == 1
    assert client.get("/extension/oauth/sessions", headers=other_headers).json() == []
    session_id = sessions.json()[0]["id"]
    assert sessions.json()[0]["organization_id"] == owner["organization_id"]
    assert sessions.json()[0]["status"] == "active"
    assert client.delete(
        f"/extension/oauth/sessions/{session_id}", headers=other_headers
    ).status_code == 404
    assert client.delete(
        f"/extension/oauth/sessions/{session_id}", headers=owner_headers
    ).status_code == 204
    assert client.get("/extension/oauth/sessions", headers=owner_headers).json()[0]["status"] == "revoked"
    assert client.post(
        "/extension/v1/scans",
        headers={"Authorization": f"Bearer {extension_token}"},
        json={"url": "https://example.test"},
    ).status_code == 401


def test_extension_authorization_page_uses_private_headers(client: TestClient):
    response = client.get("/extension/authorize")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "Your password is not sent to the extension" in response.text
    assert "cannot manage members" in response.text

