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

from apps.api import assets, auth, emailer, extension_auth, main, notification_worker, rate_limits
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import (
    AuditEvent,
    Base,
    CaseFinding,
    DomainAsset,
    EmailActionToken,
    ExtensionAuthorizationCode,
    ExtensionSession,
    Finding,
    IncidentCase,
    Membership,
    ScanEvidence,
    SecurityNotificationOutbox,
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
    assert verified.json()["dns_value"] is None

    with client.app.state.test_session_factory() as session:
        asset = session.get(DomainAsset, asset_data["id"])
        audit = session.scalars(
            select(AuditEvent).where(AuditEvent.target_id == asset_data["id"])
        ).all()
        assert asset.status == "verified"
        assert asset.verification_token_hash is None
        assert {event.action for event in audit} == {"domain_asset.created", "domain_asset.verified"}


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
        assert client.delete(f"{path}/{asset_id}", headers=headers).status_code == 403


def test_cases_group_scan_findings_with_tenant_isolation_and_audited_lifecycle(client: TestClient):
    owner = register(client, "case-owner@example.test")
    other = register(client, "case-other@example.test")
    analyst = register(client, "case-analyst@example.test")
    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    with client.app.state.test_session_factory() as session, session.begin():
        analyst_user = session.scalar(select(User).where(User.email_normalized == "case-analyst@example.test"))
        assert analyst_user is not None
        session.add(Membership(
            organization_id=owner["organization_id"], user_id=analyst_user.id, role="analyst"
        ))

    scan_response = client.post(
        f"/organizations/{owner['organization_id']}/scans",
        headers=owner_headers,
        json={"url": "https://alice:secret@example.com/path?access_token=topsecret"},
    )
    assert scan_response.status_code == 201
    scan = scan_response.json()
    assert scan["findings"]
    automatic_cases = client.get(
        f"/organizations/{owner['organization_id']}/cases", headers=owner_headers
    )
    assert automatic_cases.status_code == 200
    assert len(automatic_cases.json()) == 1
    assert automatic_cases.json()[0]["severity"] == "high"
    assert "not a safety verdict" in automatic_cases.json()[0]["summary"]
    delivery_status = client.get(
        f"/organizations/{owner['organization_id']}/notification-status", headers=owner_headers
    )
    assert delivery_status.status_code == 200
    assert delivery_status.json()["pending_count"] == 1
    assert delivery_status.json()["failed_count"] == 0
    assert delivery_status.json()["oldest_pending_at"] is not None
    assert client.get(
        f"/organizations/{owner['organization_id']}/notification-status",
        headers={"Authorization": f"Bearer {analyst['access_token']}"},
    ).status_code == 403

    case_response = client.post(
        f"/organizations/{owner['organization_id']}/cases/from-scan/{scan['id']}",
        headers=owner_headers,
    )
    assert case_response.status_code == 200
    case = case_response.json()
    assert case["id"] == automatic_cases.json()[0]["id"]
    assert case["status"] == "open"
    assert case["hostname"] == "example.com"
    assert len(case["findings"]) == len(scan["findings"])
    assert "topsecret" not in case_response.text

    duplicate = client.post(
        f"/organizations/{owner['organization_id']}/cases/from-scan/{scan['id']}",
        headers=owner_headers,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["id"] == case["id"]

    assert client.get(
        f"/organizations/{owner['organization_id']}/cases/{case['id']}", headers=other_headers
    ).status_code == 404
    assert client.get(
        f"/organizations/{owner['organization_id']}/cases", headers=other_headers
    ).status_code == 404

    invalid_transition = client.patch(
        f"/organizations/{owner['organization_id']}/cases/{case['id']}/status",
        headers=owner_headers,
        json={"status": "awaiting_approval"},
    )
    assert invalid_transition.status_code == 409
    for next_status in ("investigating", "awaiting_approval", "resolved"):
        updated = client.patch(
            f"/organizations/{owner['organization_id']}/cases/{case['id']}/status",
            headers=owner_headers,
            json={"status": next_status},
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == next_status
    assert updated.json()["closed_at"] is not None

    with client.app.state.test_session_factory() as session:
        stored = session.get(IncidentCase, case["id"])
        links = session.scalars(
            select(CaseFinding).where(CaseFinding.case_id == case["id"])
        ).all()
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.target_id == case["id"])
        ).all()
        assert stored.status == "resolved"
        assert stored.created_by_user_id is None
        assert len(links) == len(scan["findings"])
        assert sum(event.action == "case.status_changed" for event in events) == 3
        assert any(
            event.action == "case.auto_created_from_scan" and event.actor_type == "system"
            for event in events
        )
        notifications = session.scalars(
            select(SecurityNotificationOutbox).where(SecurityNotificationOutbox.case_id == case["id"])
        ).all()
        owner_membership = session.scalar(select(Membership).where(
            Membership.organization_id == owner["organization_id"], Membership.role == "owner"
        ))
        assert len(notifications) == 1
        assert owner_membership is not None and notifications[0].user_id == owner_membership.user_id


def test_soc_case_and_scan_permissions_follow_membership_role(client: TestClient):
    owner = register(client, "permissions-owner@example.test")
    analyst = register(client, "permissions-analyst@example.test")
    viewer = register(client, "permissions-viewer@example.test")
    other = register(client, "permissions-other@example.test")
    with client.app.state.test_session_factory() as session:
        for email, role in (("permissions-analyst@example.test", "analyst"), ("permissions-viewer@example.test", "viewer")):
            user = session.scalar(select(User).where(User.email_normalized == email))
            session.add(Membership(
                organization_id=owner["organization_id"], user_id=user.id, role=role,
            ))
        session.commit()

    organization_url = f"/organizations/{owner['organization_id']}"
    scan = client.post(
        f"{organization_url}/scans",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"url": "https://alice:secret@example.com/login?token=redacted"},
    )
    assert scan.status_code == 201
    scan_id = scan.json()["id"]
    case = client.get(organization_url + "/cases", headers={
        "Authorization": f"Bearer {owner['access_token']}",
    }).json()[0]
    case_url = organization_url + f"/cases/{case['id']}"
    scan_url = organization_url + f"/scans/{scan_id}"

    analyst_headers = {"Authorization": f"Bearer {analyst['access_token']}"}
    viewer_headers = {"Authorization": f"Bearer {viewer['access_token']}"}
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    assert client.get(scan_url, headers=analyst_headers).status_code == 200
    assert client.get(case_url, headers=analyst_headers).status_code == 200
    assert client.patch(case_url + "/status", headers=analyst_headers, json={"status": "investigating"}).status_code == 200

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

    assert client.get(case_url, headers=other_headers).status_code == 404
    assert client.get(scan_url, headers=other_headers).status_code == 404


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
        json={"url": "https://example.test/path?session=private"},
    )
    assert scan.status_code == 201
    assert scan.json()["display_url"] == "https://example.test/[path and query omitted]"
    assert "private" not in scan.text
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
    payload = {
        "client_id": "securelink-chrome-extension",
        "redirect_uri": "https://attacker.example.test/callback",
        "organization_id": owner["organization_id"],
        "state": "s" * 43,
        "code_challenge": _challenge("v" * 43),
        "code_challenge_method": "S256",
    }
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    assert client.post("/extension/oauth/authorize", headers=headers, json=payload).status_code == 400

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
