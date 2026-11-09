from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import auth, main
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import Base

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

    invalid_token = client.get(
        "/organizations/not-an-org",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert invalid_token.status_code == 401


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
