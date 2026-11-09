import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from packages.security_core.models import AuditEvent, Base, Membership, Organization, User


def make_user(email: str) -> User:
    return User(
        email=email,
        email_normalized=email.lower(),
        password_hash="test-hash",
    )


def test_tenant_identity_schema_creates_and_enforces_membership_role():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        user = make_user("analyst@example.test")
        organization = Organization(name="Example")
        session.add_all([user, organization])
        session.flush()
        membership = Membership(user_id=user.id, organization_id=organization.id, role="analyst")
        session.add(membership)
        session.commit()
        assert membership.organization_id == organization.id

        session.add(Membership(user_id=user.id, organization_id=organization.id, role="root"))
        with pytest.raises(IntegrityError):
            session.commit()
    engine.dispose()


def test_audit_event_is_scoped_to_organization_and_actor():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        user = make_user("owner@example.test")
        organization = Organization(name="Example")
        session.add_all([user, organization])
        session.flush()
        event = AuditEvent(
            organization_id=organization.id,
            actor_user_id=user.id,
            actor_type="user",
            action="organization.created",
            target_type="organization",
            target_id=organization.id,
            details='{"source":"test"}',
        )
        session.add(event)
        session.commit()
        assert event.organization_id == organization.id
        assert event.actor_user_id == user.id
    engine.dispose()
