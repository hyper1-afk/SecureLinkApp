from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import auth, main, rate_limits
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import AuditEvent, Base, EmailActionToken, Membership, User

TEST_SECRET = "test-secret-key-with-at-least-32-bytes"


class FakeRedis:
    def __init__(self):
        self.counts = {}

    def eval(self, _script, _key_count, key, _window):
        count = self.counts.get(key, 0) + 1
        self.counts[key] = count
        return [count, 3600]

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
    sent_emails: list[tuple[str, str, str]] = []
    monkeypatch.setattr(auth, "get_settings", lambda: Settings(
        app_secret_key=TEST_SECRET,
        smtp_host="mail.example.test",
        smtp_from_email="no-reply@example.test",
    ))
    redis = FakeRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)

    def fake_send(purpose: str, email: str, token: str) -> None:
        sent_emails.append((purpose, email, token))

    monkeypatch.setattr(auth, "send_action_email", fake_send)
    monkeypatch.setattr(auth, "email_delivery_configured", lambda: True)

    def override_session():
        with factory() as session:
            yield session

    main.app.state.test_session_factory = factory
    main.app.state.sent_emails = sent_emails
    main.app.dependency_overrides[get_session] = override_session
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.dependency_overrides.clear()
    engine.dispose()


def register_unverified(client: TestClient, email: str) -> None:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "a-long-test-password",
            "organization_name": "Example Org",
        },
    )
    assert response.status_code == 202
    assert response.json()["message"]


def register(client: TestClient, email: str) -> dict[str, str]:
    register_unverified(client, email)
    purpose, sent_to, verify_token = client.app.state.sent_emails[-1]
    assert (purpose, sent_to) == ("verify_email", email)
    verified = client.post("/auth/verify-email", json={"token": verify_token})
    assert verified.status_code == 200

    login = client.post(
        "/auth/login",
        json={"email": email, "password": "a-long-test-password"},
    )
    assert login.status_code == 200
    return login.json()


def test_registration_requires_email_verification_before_login(client: TestClient):
    register_unverified(client, "pending@example.test")
    rejected = client.post(
        "/auth/login",
        json={"email": "pending@example.test", "password": "a-long-test-password"},
    )
    assert rejected.status_code == 401

    purpose, sent_to, token = client.app.state.sent_emails[-1]
    assert (purpose, sent_to) == ("verify_email", "pending@example.test")
    with client.app.state.test_session_factory() as session:
        stored_hash = session.scalar(
            select(EmailActionToken.token_hash).where(EmailActionToken.purpose == "verify_email")
        )
    assert stored_hash != token
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400


def test_registration_creates_owner_and_login_issues_access_token(client: TestClient):
    registered = register(client, "owner@example.test")
    assert registered["token_type"] == "bearer"
    assert registered["expires_in"] == 900
    response = client.get(
        f"/organizations/{registered['organization_id']}",
        headers={"Authorization": f"Bearer {registered['access_token']}"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "owner"
    with client.app.state.test_session_factory() as session:
        login_events = session.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "user.login")
        )
    assert login_events == 1


def test_user_cannot_read_another_organizations_record(client: TestClient):
    first = register(client, "first@example.test")
    second = register(client, "second@example.test")
    response = client.get(
        f"/organizations/{second['organization_id']}",
        headers={"Authorization": f"Bearer {first['access_token']}"},
    )
    assert response.status_code == 404


def test_authentication_rejects_invalid_credentials_and_tokens(client: TestClient):
    register(client, "person@example.test")
    invalid_login = client.post(
        "/auth/login",
        json={"email": "person@example.test", "password": "incorrect-password"},
    )
    assert invalid_login.status_code == 401
    unknown_login = client.post(
        "/auth/login",
        json={"email": "missing@example.test", "password": "incorrect-password"},
    )
    assert unknown_login.status_code == 401

    invalid_token = client.get(
        "/organizations/not-an-org",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert invalid_token.status_code == 401

    registered = register(client, "token@example.test")
    tampered_token = f"x{registered['access_token'][1:]}"
    tampered = client.get(
        f"/organizations/{registered['organization_id']}",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert tampered.status_code == 401


def test_only_owners_and_admins_can_list_organization_members(client: TestClient):
    owner = register(client, "team-owner@example.test")
    viewer = register(client, "team-viewer@example.test")
    with client.app.state.test_session_factory() as session:
        viewer_id = session.scalar(
            select(User.id).where(User.email_normalized == "team-viewer@example.test")
        )
        session.add(
            Membership(
                organization_id=owner["organization_id"],
                user_id=viewer_id,
                role="viewer",
            )
        )
        session.commit()

    owner_response = client.get(
        f"/organizations/{owner['organization_id']}/members",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    )
    assert owner_response.status_code == 200
    assert {item["role"] for item in owner_response.json()} == {"owner", "viewer"}

    viewer_response = client.get(
        f"/organizations/{owner['organization_id']}/members",
        headers={"Authorization": f"Bearer {viewer['access_token']}"},
    )
    assert viewer_response.status_code == 403


def test_disabling_a_user_invalidates_existing_access_tokens(client: TestClient):
    registered = register(client, "disabled@example.test")
    with client.app.state.test_session_factory() as session:
        session.execute(
            update(User)
            .where(User.email_normalized == "disabled@example.test")
            .values(is_active=False)
        )
        session.commit()

    response = client.get(
        f"/organizations/{registered['organization_id']}",
        headers={"Authorization": f"Bearer {registered['access_token']}"},
    )
    assert response.status_code == 401


def test_duplicate_email_registration_is_rejected_without_disclosing_existence(client: TestClient):
    register_unverified(client, "duplicate@example.test")
    first_message = client.post(
        "/auth/verification/resend",
        json={"email": "missing@example.test"},
    )
    duplicate = client.post(
        "/auth/register",
        json={
            "email": "DUPLICATE@example.test",
            "password": "another-long-password",
            "organization_name": "Second Org",
        },
    )
    assert duplicate.status_code == 202
    assert duplicate.json()["message"] == first_message.json()["message"]


def test_password_reset_revokes_prior_tokens_and_changes_password(client: TestClient):
    registered = register(client, "reset@example.test")
    forgot = client.post("/auth/password/forgot", json={"email": "reset@example.test"})
    assert forgot.status_code == 200
    purpose, sent_to, reset_token = client.app.state.sent_emails[-1]
    assert (purpose, sent_to) == ("reset_password", "reset@example.test")

    reset = client.post(
        "/auth/password/reset",
        json={"token": reset_token, "new_password": "a-different-long-password"},
    )
    assert reset.status_code == 200

    old_access = client.get(
        f"/organizations/{registered['organization_id']}",
        headers={"Authorization": f"Bearer {registered['access_token']}"},
    )
    assert old_access.status_code == 401
    old_password = client.post(
        "/auth/login",
        json={"email": "reset@example.test", "password": "a-long-test-password"},
    )
    assert old_password.status_code == 401
    new_password = client.post(
        "/auth/login",
        json={"email": "reset@example.test", "password": "a-different-long-password"},
    )
    assert new_password.status_code == 200


def test_registration_requires_configured_email_delivery(client: TestClient, monkeypatch):
    monkeypatch.setattr(auth, "email_delivery_configured", lambda: False)
    response = client.post(
        "/auth/register",
        json={
            "email": "unconfigured@example.test",
            "password": "a-long-test-password",
            "organization_name": "Example Org",
        },
    )
    assert response.status_code == 503
