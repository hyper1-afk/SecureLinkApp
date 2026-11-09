import json
from collections.abc import Generator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import auth, emailer, main, rate_limits
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import (
    Base,
    EmailActionToken,
    Finding,
    Membership,
    ScanEvidence,
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
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
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


def test_dashboard_page_uses_private_headers_and_discloses_scan_limits(client: TestClient):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "does not fetch the submitted URL" in response.text
    assert "not a safety verdict" in response.text
