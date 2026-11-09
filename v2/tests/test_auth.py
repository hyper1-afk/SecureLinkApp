from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import auth, main
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import AuditEvent, Base, Membership, User

TEST_SECRET = "test-secret-key-with-at-least-32-bytes"


@pytest.fixture
def client(monkeypatch) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_session():
        with factory() as session:
            yield session

    monkeypatch.setattr(auth, "get_settings", lambda: Settings(app_secret_key=TEST_SECRET))
    main.app.state.test_session_factory = factory
    main.app.dependency_overrides[get_session] = override_session
    with TestClient(main.app) as test_client:
        yield test_client
    main.app.dependency_overrides.clear()
    engine.dispose()


def register(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "a-long-test-password",
            "organization_name": "Example Org",
        },
    )
    assert response.status_code == 201
    return response.json()


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

    login = client.post(
        "/auth/login",
        json={"email": "OWNER@example.test", "password": "a-long-test-password"},
    )
    assert login.status_code == 200
    assert login.json()["organization_id"] == registered["organization_id"]
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
    token = registered["access_token"]
    tampered_token = f"x{token[1:]}"
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


def test_duplicate_email_registration_is_rejected(client: TestClient):
    register(client, "duplicate@example.test")
    response = client.post(
        "/auth/register",
        json={
            "email": "DUPLICATE@example.test",
            "password": "another-long-password",
            "organization_name": "Second Org",
        },
    )
    assert response.status_code == 409


def test_registration_requires_configured_signing_secret(client: TestClient, monkeypatch):
    monkeypatch.setattr(auth, "get_settings", lambda: Settings(app_secret_key=None))
    response = client.post(
        "/auth/register",
        json={
            "email": "unconfigured@example.test",
            "password": "a-long-test-password",
            "organization_name": "Example Org",
        },
    )
    assert response.status_code == 503
