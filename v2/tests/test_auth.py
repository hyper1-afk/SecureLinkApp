from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api import auth, email_worker, emailer, main, mfa, rate_limits
from apps.api.config import Settings
from apps.api.db import get_session
from packages.security_core.models import (
    AuditEvent,
    Base,
    EmailActionToken,
    Membership,
    MFARecoveryCode,
    User,
)

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
        mfa_encryption_key=Fernet.generate_key().decode("ascii"),
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
    mfa_status = client.get("/auth/mfa", headers={"Authorization": f"Bearer {registered['access_token']}"})
    assert mfa_status.json()["required"] is True
    assert mfa_status.json()["grace_expires_at"] is not None
    assert mfa_status.headers["cache-control"] == "no-store"
    with client.app.state.test_session_factory() as session:
        login_events = session.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "user.login")
        )
    assert login_events == 1


def test_mfa_enrollment_login_recovery_and_disable(client: TestClient):
    registered = register(client, "mfa@example.test")
    headers = {"Authorization": f"Bearer {registered['access_token']}"}
    enrollment = client.post("/auth/mfa/enrollment", headers=headers)
    assert enrollment.status_code == 200
    secret = enrollment.json()["secret"]
    confirmation_code = mfa.totp_code(secret)
    confirmed = client.post("/auth/mfa/confirm", headers=headers, json={"code": confirmation_code})
    assert confirmed.status_code == 200
    assert client.get(f"/organizations/{registered['organization_id']}", headers=headers).status_code == 401
    refreshed_login = client.post("/auth/login", json={
        "email": "mfa@example.test", "password": "a-long-test-password", "mfa_code": mfa.totp_code(secret),
    })
    assert refreshed_login.status_code == 200
    headers = {"Authorization": f"Bearer {refreshed_login.json()['access_token']}"}
    recovery_codes = confirmed.json()["recovery_codes"]
    assert len(recovery_codes) == 10
    assert all(len(code) == 24 for code in recovery_codes)
    with client.app.state.test_session_factory() as session:
        stored_recovery_hashes = session.scalars(select(MFARecoveryCode.code_hash)).all()
    assert len(stored_recovery_hashes) == 10
    assert not any(code in stored_recovery_hashes for code in recovery_codes)

    no_code = client.post("/auth/login", json={"email": "mfa@example.test", "password": "a-long-test-password"})
    assert no_code.status_code == 401
    login = client.post("/auth/login", json={
        "email": "mfa@example.test", "password": "a-long-test-password", "mfa_code": mfa.totp_code(secret),
    })
    assert login.status_code == 200
    recovery_login = client.post("/auth/login", json={
        "email": "mfa@example.test", "password": "a-long-test-password", "mfa_code": recovery_codes[0],
    })
    assert recovery_login.status_code == 200
    replayed_recovery = client.post("/auth/login", json={
        "email": "mfa@example.test", "password": "a-long-test-password", "mfa_code": recovery_codes[0],
    })
    assert replayed_recovery.status_code == 401

    with client.app.state.test_session_factory() as session:
        user = session.scalar(select(User).where(User.email_normalized == "mfa@example.test"))
        session.execute(update(Membership).where(Membership.user_id == user.id).values(role="viewer"))
        session.commit()

    disable = client.post("/auth/mfa/disable", headers=headers, json={
        "password": "a-long-test-password", "code": mfa.totp_code(secret),
    })
    assert disable.status_code == 200
    assert disable.json()["enabled"] is False
    assert client.get(f"/organizations/{registered['organization_id']}", headers=headers).status_code == 401
    assert client.post("/auth/login", json={"email": "mfa@example.test", "password": "a-long-test-password"}).status_code == 200


def _enable_mfa(client: TestClient, email: str) -> tuple[dict[str, str], str, list[str]]:
    registered = register(client, email)
    headers = {"Authorization": f"Bearer {registered['access_token']}"}
    enrollment = client.post("/auth/mfa/enrollment", headers=headers)
    secret = enrollment.json()["secret"]
    confirmed = client.post("/auth/mfa/confirm", headers=headers, json={"code": mfa.totp_code(secret)})
    assert confirmed.status_code == 200
    logged_in = client.post("/auth/login", json={
        "email": email, "password": "a-long-test-password", "mfa_code": mfa.totp_code(secret),
    })
    assert logged_in.status_code == 200
    return {**registered, "access_token": logged_in.json()["access_token"]}, secret, confirmed.json()["recovery_codes"]


def test_mfa_rotation_preserves_old_factor_until_confirm_then_revokes_sessions(client: TestClient):
    registered, old_secret, old_recovery_codes = _enable_mfa(client, "rotate@example.test")
    headers = {"Authorization": f"Bearer {registered['access_token']}"}
    started = client.post("/auth/mfa/rotation", headers=headers, json={
        "password": "a-long-test-password", "code": mfa.totp_code(old_secret),
    })
    assert started.status_code == 200
    new_secret = started.json()["secret"]
    assert client.get("/auth/mfa", headers=headers).status_code == 200

    confirmed = client.post("/auth/mfa/rotation/confirm", headers=headers, json={
        "code": mfa.totp_code(new_secret),
    })
    assert confirmed.status_code == 200
    new_recovery_codes = confirmed.json()["recovery_codes"]
    assert len(new_recovery_codes) == 10
    assert client.get(f"/organizations/{registered['organization_id']}", headers=headers).status_code == 401
    assert client.post("/auth/login", json={
        "email": "rotate@example.test", "password": "a-long-test-password", "mfa_code": mfa.totp_code(old_secret),
    }).status_code == 401
    assert client.post("/auth/login", json={
        "email": "rotate@example.test", "password": "a-long-test-password", "mfa_code": mfa.totp_code(new_secret),
    }).status_code == 200
    assert client.post("/auth/login", json={
        "email": "rotate@example.test", "password": "a-long-test-password", "mfa_code": old_recovery_codes[1],
    }).status_code == 401
    assert client.post("/auth/login", json={
        "email": "rotate@example.test", "password": "a-long-test-password", "mfa_code": new_recovery_codes[0],
    }).status_code == 200
    with client.app.state.test_session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == "user.mfa_rotated",
        )) == 1


def test_mfa_rotation_accepts_recovery_code_and_rejects_bad_password(client: TestClient):
    registered, old_secret, recovery_codes = _enable_mfa(client, "rotate-recovery@example.test")
    headers = {"Authorization": f"Bearer {registered['access_token']}"}
    bad_password = client.post("/auth/mfa/rotation", headers=headers, json={
        "password": "wrong-password", "code": mfa.totp_code(old_secret),
    })
    assert bad_password.status_code == 400

    started = client.post("/auth/mfa/rotation", headers=headers, json={
        "password": "a-long-test-password", "code": recovery_codes[0],
    })
    assert started.status_code == 200
    new_secret = started.json()["secret"]
    with client.app.state.test_session_factory() as session:
        consumed = session.scalar(select(MFARecoveryCode).where(
            MFARecoveryCode.code_hash == auth.recovery_code_hash(recovery_codes[0]),
        ))
        assert consumed is not None and consumed.consumed_at is not None
    assert client.post("/auth/mfa/rotation/confirm", headers=headers, json={
        "code": mfa.totp_code(new_secret),
    }).status_code == 200
    replay = client.post("/auth/mfa/rotation", headers=headers, json={
        "password": "a-long-test-password", "code": recovery_codes[0],
    })
    assert replay.status_code == 401


def test_privileged_mfa_grace_expires_and_enrolled_admin_cannot_disable(client: TestClient):
    owner = register(client, "mfa-required@example.test")
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    with client.app.state.test_session_factory() as session:
        user = session.scalar(select(User).where(User.email_normalized == "mfa-required@example.test"))
        user.privileged_mfa_grace_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    blocked = client.get(f"/organizations/{owner['organization_id']}", headers=headers)
    assert blocked.status_code == 403
    assert "MFA enrollment is required" in blocked.json()["detail"]
    assert client.get("/auth/mfa", headers=headers).json()["required"] is True

    enrollment = client.post("/auth/mfa/enrollment", headers=headers)
    secret = enrollment.json()["secret"]
    enabled = client.post(
        "/auth/mfa/confirm", headers=headers, json={"code": mfa.totp_code(secret)}
    )
    assert enabled.status_code == 200
    assert client.get(f"/organizations/{owner['organization_id']}", headers=headers).status_code == 401
    logged_in = client.post("/auth/login", json={
        "email": "mfa-required@example.test", "password": "a-long-test-password", "mfa_code": mfa.totp_code(secret),
    })
    assert logged_in.status_code == 200
    headers = {"Authorization": f"Bearer {logged_in.json()['access_token']}"}
    assert client.get(f"/organizations/{owner['organization_id']}", headers=headers).status_code == 200
    assert client.get("/auth/mfa", headers=headers).json()["can_disable"] is False
    cannot_disable = client.post(
        "/auth/mfa/disable",
        headers=headers,
        json={"password": "a-long-test-password", "code": mfa.totp_code(secret)},
    )
    assert cannot_disable.status_code == 403


def test_totp_matches_rfc_6238_sha1_vector():
    assert mfa.totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", timestamp=59) == "287082"


def test_owner_transfer_requires_mfa_and_targets_existing_admin(client: TestClient):
    owner = register(client, "transfer-owner@example.test")
    register(client, "transfer-successor@example.test")
    with client.app.state.test_session_factory() as session:
        successor_user = session.scalar(
            select(User).where(User.email_normalized == "transfer-successor@example.test")
        )
        successor_membership = Membership(
            organization_id=owner["organization_id"], user_id=successor_user.id, role="admin"
        )
        session.add(successor_membership)
        session.commit()
        successor_membership_id = successor_membership.id

    owner_headers = {"Authorization": f"Bearer {owner['access_token']}"}
    transfer_url = f"/organizations/{owner['organization_id']}/owner-transfer"
    no_mfa = client.post(transfer_url, headers=owner_headers, json={
        "target_membership_id": successor_membership_id,
        "password": "a-long-test-password",
        "mfa_code": "123456",
    })
    assert no_mfa.status_code == 403

    enrollment = client.post("/auth/mfa/enrollment", headers=owner_headers)
    secret = enrollment.json()["secret"]
    confirmed = client.post(
        "/auth/mfa/confirm", headers=owner_headers, json={"code": mfa.totp_code(secret)}
    )
    assert confirmed.status_code == 200
    assert client.get(f"/organizations/{owner['organization_id']}", headers=owner_headers).status_code == 401
    owner_login = client.post("/auth/login", json={
        "email": "transfer-owner@example.test", "password": "a-long-test-password", "mfa_code": mfa.totp_code(secret),
    })
    owner_headers = {"Authorization": f"Bearer {owner_login.json()['access_token']}"}
    transferred = client.post(transfer_url, headers=owner_headers, json={
        "target_membership_id": successor_membership_id,
        "password": "a-long-test-password",
        "mfa_code": mfa.totp_code(secret),
    })
    assert transferred.status_code == 200
    assert transferred.json()["role"] == "owner"
    with client.app.state.test_session_factory() as session:
        roles = session.scalars(
            select(Membership.role).where(Membership.organization_id == owner["organization_id"])
        ).all()
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "membership.ownership_transferred")
        )
    assert roles.count("owner") == 1
    assert event is not None and event.target_id == successor_membership_id


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
        session.execute(
            update(User)
            .where(User.id == analyst_user_id)
            .values(privileged_mfa_grace_expires_at=None)
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
        json={"role": "admin"},
    )
    assert changed.status_code == 200
    assert changed.json()["role"] == "admin"
    with client.app.state.test_session_factory() as session:
        target_user = session.get(User, changed.json()["user_id"])
        deadline = target_user.privileged_mfa_grace_expires_at
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        assert deadline > datetime.now(UTC)

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


def test_user_can_list_all_organizations_they_belong_to(client: TestClient):
    owner = register(client, "multi-org-owner@example.test")
    teammate = register(client, "multi-org-teammate@example.test")
    response = client.post(
        f"/organizations/{owner['organization_id']}/invitations",
        headers={"Authorization": f"Bearer {owner['access_token']}"},
        json={"email": "multi-org-teammate@example.test", "role": "viewer"},
    )
    assert response.status_code == 202

    with client.app.state.test_session_factory() as session:
        action = session.scalar(
            select(EmailActionToken)
            .join(User, User.id == EmailActionToken.user_id)
            .where(
                EmailActionToken.purpose == "invite_member",
                User.email_normalized == "multi-org-teammate@example.test",
                EmailActionToken.organization_id == owner["organization_id"],
            )
        )
        assert action is not None and action.delivery_ciphertext is not None
        invitation_token = emailer.decrypt_action_token(action.delivery_ciphertext)
    accepted = client.post("/auth/invitations/accept", json={"token": invitation_token})
    assert accepted.status_code == 200

    organizations_response = client.get(
        "/auth/organizations",
        headers={"Authorization": f"Bearer {teammate['access_token']}"},
    )
    assert organizations_response.status_code == 200
    assert organizations_response.headers["cache-control"] == "no-store"
    memberships = organizations_response.json()
    assert {item["id"] for item in memberships} == {
        owner["organization_id"],
        teammate["organization_id"],
    }
    assert {item["role"] for item in memberships} == {"owner", "viewer"}
    assert client.get("/auth/organizations").status_code == 401


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
