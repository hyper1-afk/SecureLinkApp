from collections.abc import Generator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import auth, email_worker, emailer, main, rate_limits
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
    test_settings = Settings(
        app_secret_key=TEST_SECRET,
        smtp_host="mail.example.test",
        smtp_from_email="no-reply@example.test",
        email_outbox_encryption_key=Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setattr(auth, "get_settings", lambda: test_settings)
    monkeypatch.setattr(emailer, "get_settings", lambda: test_settings)
    monkeypatch.setattr(email_worker, "get_session_factory", lambda: factory)
    redis = FakeRedis()
    monkeypatch.setattr(rate_limits, "get_rate_limit_client", lambda: redis)

    monkeypatch.setattr(auth, "email_delivery_configured", lambda: True)

    def override_session():
        with factory() as session:
            yield session

    main.app.state.test_session_factory = factory
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


def action_token(client: TestClient, purpose: str, email: str) -> str:
    with client.app.state.test_session_factory() as session:
        row = session.scalar(
            select(EmailActionToken)
            .join(User, User.id == EmailActionToken.user_id)
            .where(
                EmailActionToken.purpose == purpose,
                User.email_normalized == email.casefold(),
            )
        )
        assert row is not None and row.delivery_ciphertext is not None
        return emailer.decrypt_action_token(row.delivery_ciphertext)


def register(client: TestClient, email: str) -> dict[str, str]:
    register_unverified(client, email)
    verify_token = action_token(client, "verify_email", email)
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

    token = action_token(client, "verify_email", "pending@example.test")
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
    reset_token = action_token(client, "reset_password", "reset@example.test")

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



def test_email_worker_sends_and_clears_encrypted_payload(client: TestClient, monkeypatch):
    register_unverified(client, "worker@example.test")
    delivered = []
    monkeypatch.setattr(email_worker, "send_action_email", lambda purpose, recipient, token: delivered.append((purpose, recipient, token)))
    assert email_worker.process_one()
    assert delivered[0][0:2] == ("verify_email", "worker@example.test")
    with client.app.state.test_session_factory() as session:
        row = session.scalar(select(EmailActionToken).where(EmailActionToken.purpose == "verify_email"))
        assert row.delivery_state == "sent"
        assert row.delivery_ciphertext is None
        assert row.delivered_at is not None


def test_email_worker_retries_without_logging_token_or_recipient(client: TestClient, monkeypatch, caplog):
    register_unverified(client, "retry@example.test")
    token = action_token(client, "verify_email", "retry@example.test")
    monkeypatch.setattr(email_worker, "send_action_email", lambda *_args: (_ for _ in ()).throw(OSError("smtp down")))
    assert email_worker.process_one()
    with client.app.state.test_session_factory() as session:
        row = session.scalar(select(EmailActionToken).where(EmailActionToken.purpose == "verify_email"))
        assert row.delivery_state == "pending"
        assert row.delivery_attempts == 1
        assert row.delivery_ciphertext is not None
    assert token not in caplog.text
    assert "retry@example.test" not in caplog.text



def test_owner_can_change_roles_and_mutations_create_audit_events(client: TestClient):
    owner = register(client, "role-owner@example.test")
    register(client, "role-analyst@example.test")
    with client.app.state.test_session_factory() as session:
        analyst_user_id = session.scalar(
            select(User.id).where(User.email_normalized == "role-analyst@example.test")
        )
        analyst_membership = Membership(
            organization_id=owner["organization_id"],
            user_id=analyst_user_id,
            role="viewer",
        )
        session.add(analyst_membership)
        session.commit()
        analyst_membership_id = analyst_membership.id

    changed = client.patch(
        f"/organizations/{owner['organization_id']}/members/{analyst_membership_id}",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"role": "analyst"},
    )
    assert changed.status_code == 200
    assert changed.json()["role"] == "analyst"

    removed = client.delete(
        f"/organizations/{owner['organization_id']}/members/{analyst_membership_id}",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
    )
    assert removed.status_code == 204
    with client.app.state.test_session_factory() as session:
        actions = set(session.scalars(
            select(AuditEvent.action).where(
                AuditEvent.action.in_(["membership.role_changed", "membership.removed"])
            )
        ))
    assert actions == {"membership.role_changed", "membership.removed"}


def test_last_owner_cannot_be_demoted_or_removed(client: TestClient):
    owner = register(client, "last-owner@example.test")
    with client.app.state.test_session_factory() as session:
        owner_membership_id = session.scalar(
            select(Membership.id).where(
                Membership.organization_id == owner["organization_id"],
                Membership.role == "owner",
            )
        )

    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    path = f"/organizations/{owner['organization_id']}/members/{owner_membership_id}"
    demote = client.patch(path, headers=headers, json={"role": "admin"})
    remove = client.delete(path, headers=headers)
    assert demote.status_code == 409
    assert remove.status_code == 409


def test_admin_cannot_manage_another_admin_or_grant_admin_role(client: TestClient):
    owner = register(client, "org-owner@example.test")
    admin = register(client, "org-admin@example.test")
    register(client, "org-analyst@example.test")
    with client.app.state.test_session_factory() as session:
        admin_user = session.scalar(select(User).where(User.email_normalized == "org-admin@example.test"))
        analyst_user = session.scalar(select(User).where(User.email_normalized == "org-analyst@example.test"))
        admin_member = Membership(
            organization_id=owner["organization_id"],
            user_id=admin_user.id,
            role="admin",
        )
        analyst_member = Membership(
            organization_id=owner["organization_id"],
            user_id=analyst_user.id,
            role="analyst",
        )
        session.add_all([admin_member, analyst_member])
        session.commit()
        owner_membership_id = session.scalar(
            select(Membership.id).where(
                Membership.organization_id == owner["organization_id"],
                Membership.role == "owner",
            )
        )
        admin_membership_id = admin_member.id
        analyst_membership_id = analyst_member.id

    headers = {"Authorization": f"Bearer {admin['access_token']}"}
    promote_admin = client.patch(
        f"/organizations/{owner['organization_id']}/members/{analyst_membership_id}",
        headers=headers,
        json={"role": "admin"},
    )
    change_admin = client.patch(
        f"/organizations/{owner['organization_id']}/members/{admin_membership_id}",
        headers=headers,
        json={"role": "viewer"},
    )
    remove_owner = client.delete(
        f"/organizations/{owner['organization_id']}/members/{owner_membership_id}",
        headers=headers,
    )
    assert promote_admin.status_code == 403
    assert change_admin.status_code == 403
    assert remove_owner.status_code == 403


def test_logout_revokes_existing_access_token(client: TestClient):
    registered = register(client, "logout@example.test")
    headers = {"Authorization": f"Bearer {registered['access_token']}"}
    logout_response = client.post("/auth/logout", headers=headers)
    assert logout_response.status_code == 204

    rejected = client.get(
        f"/organizations/{registered['organization_id']}",
        headers=headers,
    )
    assert rejected.status_code == 401
    with client.app.state.test_session_factory() as session:
        logout_events = session.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "user.logout")
        )
    assert logout_events == 1


def test_invitation_requires_verified_account_and_accepts_once(client: TestClient):
    owner = register(client, "invite-owner@example.test")
    register(client, "invitee@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    invited_response = client.post(
        f"/organizations/{owner['organization_id']}/invitations",
        headers=headers,
        json={"email": "invitee@example.test", "role": "analyst"},
    )
    assert invited_response.status_code == 202
    assert "eligible" in invited_response.json()["message"]

    with client.app.state.test_session_factory() as session:
        action = session.scalar(
            select(EmailActionToken)
            .join(User, User.id == EmailActionToken.user_id)
            .where(
                EmailActionToken.purpose == "invite_member",
                EmailActionToken.organization_id == owner["organization_id"],
                User.email_normalized == "invitee@example.test",
            )
        )
        assert action is not None and action.delivery_ciphertext is not None
        invitation_token = emailer.decrypt_action_token(action.delivery_ciphertext)

    accepted = client.post("/auth/invitations/accept", json={"token": invitation_token})
    assert accepted.status_code == 200
    replay = client.post("/auth/invitations/accept", json={"token": invitation_token})
    assert replay.status_code == 400

    with client.app.state.test_session_factory() as session:
        role = session.scalar(
            select(Membership.role).where(
                Membership.organization_id == owner["organization_id"],
                Membership.user_id == session.scalar(
                    select(User.id).where(User.email_normalized == "invitee@example.test")
                ),
            )
        )
        audit_count = session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.organization_id == owner["organization_id"],
                AuditEvent.action.in_(
                    ["membership.invitation_created", "membership.invitation_accepted"]
                ),
            )
        )
    assert role == "analyst"
    assert audit_count == 2


def test_invitation_onboards_new_user_and_requires_password_setup(client: TestClient):
    owner = register(client, "new-invite-owner@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    response = client.post(
        f"/organizations/{owner['organization_id']}/invitations",
        headers=headers,
        json={"email": "new-teammate@example.test", "role": "analyst"},
    )
    assert response.status_code == 202

    with client.app.state.test_session_factory() as session:
        invited_user = session.scalar(
            select(User).where(User.email_normalized == "new-teammate@example.test")
        )
        assert invited_user is not None
        assert invited_user.invitation_setup_required is True
        assert invited_user.email_verified is False
        action = session.scalar(
            select(EmailActionToken).where(
                EmailActionToken.user_id == invited_user.id,
                EmailActionToken.purpose == "invite_member",
                EmailActionToken.organization_id == owner["organization_id"],
            )
        )
        assert action is not None and action.delivery_ciphertext is not None
        invitation_token = emailer.decrypt_action_token(action.delivery_ciphertext)

    missing_password = client.post(
        "/auth/invitations/accept", json={"token": invitation_token}
    )
    assert missing_password.status_code == 400

    accepted = client.post(
        "/auth/invitations/accept",
        json={"token": invitation_token, "password": "correct horse battery staple"},
    )
    assert accepted.status_code == 200
    login = client.post(
        "/auth/login",
        json={"email": "new-teammate@example.test", "password": "correct horse battery staple"},
    )
    assert login.status_code == 200
    assert login.json()["organization_id"] == owner["organization_id"]

    replay = client.post(
        "/auth/invitations/accept",
        json={"token": invitation_token, "password": "correct horse battery staple"},
    )
    assert replay.status_code == 400
    with client.app.state.test_session_factory() as session:
        invited_user = session.scalar(
            select(User).where(User.email_normalized == "new-teammate@example.test")
        )
        assert invited_user.email_verified is True
        assert invited_user.invitation_setup_required is False


def test_admin_cannot_invite_owner_or_admin(client: TestClient):
    owner = register(client, "invite-org-owner@example.test")
    admin = register(client, "invite-org-admin@example.test")
    register(client, "invite-target@example.test")
    with client.app.state.test_session_factory() as session:
        admin_user = session.scalar(select(User).where(User.email_normalized == "invite-org-admin@example.test"))
        session.add(
            Membership(
                organization_id=owner["organization_id"],
                user_id=admin_user.id,
                role="admin",
            )
        )
        session.commit()

    response = client.post(
        f"/organizations/{owner['organization_id']}/invitations",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
        json={"email": "invite-target@example.test", "role": "owner"},
    )
    assert response.status_code == 403
