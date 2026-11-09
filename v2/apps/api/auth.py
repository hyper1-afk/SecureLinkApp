from __future__ import annotations

import hashlib
import logging
import re
import smtplib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db import get_session
from apps.api.emailer import email_delivery_configured, send_action_email
from apps.api.rate_limits import rate_limit
from packages.security_core.models import (
    AuditEvent,
    EmailActionToken,
    Membership,
    Organization,
    User,
)

router = APIRouter()
logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False)
password_hash = PasswordHash.recommended()
dummy_password_hash = password_hash.hash("invalid-login-dummy-password")
email_pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
token_issuer = "securelink-v2"
token_audience = "securelink-v2-api"
access_token_minutes = 15
verification_lifetime = timedelta(hours=24)
reset_lifetime = timedelta(hours=1)
generic_email_message = "If the address is eligible, an email will be sent with next steps."


class RegistrationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    organization_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class EmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class ActionTokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=256)


class PasswordResetRequest(ActionTokenRequest):
    new_password: str = Field(min_length=12, max_length=128)


class MessageResponse(BaseModel):
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = access_token_minutes * 60
    organization_id: str


class Principal(BaseModel):
    user_id: str


def _secret_key() -> str:
    key = get_settings().app_secret_key
    if key is None or "replace-with" in key or len(key.encode("utf-8")) < 32:
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    return key


def _require_email_delivery() -> None:
    if not email_delivery_configured():
        raise HTTPException(status_code=503, detail="Email delivery is not configured")


def _issue_token(user_id: str, token_version: int) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": user_id,
            "ver": token_version,
            "iss": token_issuer,
            "aud": token_audience,
            "iat": now,
            "exp": now + timedelta(minutes=access_token_minutes),
            "jti": str(uuid4()),
        },
        _secret_key(),
        algorithm="HS256",
    )


def _token_response(user: User, organization_id: str) -> TokenResponse:
    return TokenResponse(
        access_token=_issue_token(user.id, user.token_version),
        organization_id=organization_id,
    )


def _new_action_token(
    session: Session,
    user: User,
    purpose: str,
    lifetime: timedelta,
) -> str:
    now = datetime.now(UTC)
    session.execute(
        update(EmailActionToken)
        .where(
            EmailActionToken.user_id == user.id,
            EmailActionToken.purpose == purpose,
            EmailActionToken.consumed_at.is_(None),
        )
        .values(consumed_at=now)
    )
    token = secrets.token_urlsafe(32)
    session.add(
        EmailActionToken(
            user_id=user.id,
            purpose=purpose,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=now + lifetime,
        )
    )
    return token


def _deliver_action_email(purpose: str, email: str, token: str) -> None:
    try:
        send_action_email(purpose, email, token)
    except (OSError, RuntimeError, smtplib.SMTPException):
        # Do not expose delivery state, recipient existence, or action tokens to the caller.
        logger.exception("Account action email delivery failed", extra={"purpose": purpose})


def _consume_action_token(
    session: Session,
    token: str,
    purpose: str,
) -> tuple[EmailActionToken, User]:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    action_token = session.scalar(
        select(EmailActionToken)
        .where(
            EmailActionToken.token_hash == digest,
            EmailActionToken.purpose == purpose,
            EmailActionToken.consumed_at.is_(None),
            EmailActionToken.expires_at > func.now(),
        )
        .with_for_update()
    )
    if action_token is None:
        raise HTTPException(status_code=400, detail="Invalid or expired action token")
    user = session.get(User, action_token.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid or expired action token")
    action_token.consumed_at = datetime.now(UTC)
    return action_token, user


@router.post(
    "/auth/register",
    response_model=MessageResponse,
    status_code=202,
    dependencies=[Depends(rate_limit("register", 5, 3600))],
)
def register(
    payload: RegistrationRequest,
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    _require_email_delivery()
    email = payload.email.strip()
    organization_name = payload.organization_name.strip()
    if not email_pattern.fullmatch(email) or not organization_name:
        raise HTTPException(status_code=422, detail="Invalid email or organization name")

    user = User(
        email=email,
        email_normalized=email.casefold(),
        password_hash=password_hash.hash(payload.password),
        email_verified=False,
    )
    organization = Organization(name=organization_name)
    token: str | None = None
    try:
        with session.begin():
            session.add_all([user, organization])
            session.flush()
            session.add(
                Membership(user_id=user.id, organization_id=organization.id, role="owner")
            )
            token = _new_action_token(session, user, "verify_email", verification_lifetime)
            session.add_all(
                [
                    AuditEvent(
                        organization_id=organization.id,
                        actor_user_id=user.id,
                        actor_type="user",
                        action="user.registered",
                        target_type="user",
                        target_id=user.id,
                        details="{}",
                    ),
                    AuditEvent(
                        organization_id=organization.id,
                        actor_user_id=user.id,
                        actor_type="user",
                        action="organization.created",
                        target_type="organization",
                        target_id=organization.id,
                        details="{}",
                    ),
                ]
            )
            session.flush()
    except IntegrityError:
        session.rollback()
        # Keep duplicate and new-address responses indistinguishable.
        return MessageResponse(message=generic_email_message)

    if token is not None:
        _deliver_action_email("verify_email", email, token)
    return MessageResponse(message=generic_email_message)


@router.post(
    "/auth/verification/resend",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("verification_resend", 3, 3600))],
)
def resend_verification(
    payload: EmailRequest,
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    _require_email_delivery()
    normalized_email = payload.email.strip().casefold()
    token: str | None = None
    email: str | None = None
    with session.begin():
        user = session.scalar(select(User).where(User.email_normalized == normalized_email))
        if user is not None and user.is_active and not user.email_verified:
            token = _new_action_token(session, user, "verify_email", verification_lifetime)
            email = user.email
    if token is not None and email is not None:
        _deliver_action_email("verify_email", email, token)
    return MessageResponse(message=generic_email_message)


def verify_email(
    payload: ActionTokenRequest,
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    with session.begin():
        _, user = _consume_action_token(session, payload.token, "verify_email")
        user.email_verified = True
        membership = session.scalar(
            select(Membership)
            .where(Membership.user_id == user.id)
            .order_by(Membership.created_at, Membership.id)
            .limit(1)
        )
        session.add(
            AuditEvent(
                organization_id=membership.organization_id if membership else None,
                actor_user_id=user.id,
                actor_type="user",
                action="user.email_verified",
                target_type="user",
                target_id=user.id,
                details="{}",
            )
        )
    return MessageResponse(message="Email address verified")


@router.post(
    "/auth/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("login", 10, 60))],
)
def login(
    payload: LoginRequest,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    _secret_key()
    user = session.scalar(
        select(User).where(User.email_normalized == payload.email.strip().casefold())
    )
    stored_hash = user.password_hash if user is not None else dummy_password_hash
    password_matches = password_hash.verify(payload.password, stored_hash)
    if user is None or not user.is_active or not user.email_verified or not password_matches:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    membership = session.scalar(
        select(Membership)
        .where(Membership.user_id == user.id)
        .order_by(Membership.created_at, Membership.id)
        .limit(1)
    )
    if membership is None:
        raise HTTPException(status_code=403, detail="Account has no organization membership")
    session.add(
        AuditEvent(
            organization_id=membership.organization_id,
            actor_user_id=user.id,
            actor_type="user",
            action="user.login",
            target_type="user",
            target_id=user.id,
            details="{}",
        )
    )
    session.commit()
    return _token_response(user, membership.organization_id)


@router.post(
    "/auth/password/forgot",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("password_forgot", 3, 3600))],
)
def forgot_password(
    payload: EmailRequest,
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    _require_email_delivery()
    normalized_email = payload.email.strip().casefold()
    token: str | None = None
    email: str | None = None
    with session.begin():
        user = session.scalar(select(User).where(User.email_normalized == normalized_email))
        if user is not None and user.is_active and user.email_verified:
            token = _new_action_token(session, user, "reset_password", reset_lifetime)
            email = user.email
    if token is not None and email is not None:
        _deliver_action_email("reset_password", email, token)
    return MessageResponse(message=generic_email_message)


def reset_password(
    payload: PasswordResetRequest,
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    with session.begin():
        _, user = _consume_action_token(session, payload.token, "reset_password")
        user.password_hash = password_hash.hash(payload.new_password)
        user.token_version += 1
        now = datetime.now(UTC)
        session.execute(
            update(EmailActionToken)
            .where(
                EmailActionToken.user_id == user.id,
                EmailActionToken.purpose == "reset_password",
                EmailActionToken.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )
        membership = session.scalar(
            select(Membership)
            .where(Membership.user_id == user.id)
            .order_by(Membership.created_at, Membership.id)
            .limit(1)
        )
        session.add(
            AuditEvent(
                organization_id=membership.organization_id if membership else None,
                actor_user_id=user.id,
                actor_type="user",
                action="user.password_reset",
                target_type="user",
                target_id=user.id,
                details="{}",
            )
        )
    return MessageResponse(message="Password reset complete")


def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Annotated[Session, Depends(get_session)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(
            credentials.credentials,
            _secret_key(),
            algorithms=["HS256"],
            audience=token_audience,
            issuer=token_issuer,
            options={"require": ["sub", "ver", "exp", "iat", "iss", "aud", "jti"]},
        )
        user_id = str(UUID(claims["sub"]))
    except (jwt.InvalidTokenError, AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = session.get(User, user_id)
    if user is None or not user.is_active or claims["ver"] != user.token_version:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(user_id=user_id)


def organization_membership(
    organization_id: str,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> Membership:
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == principal.user_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return membership


def require_org_admin(
    membership: Annotated[Membership, Depends(organization_membership)],
) -> Membership:
    if membership.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Owner or admin role required")
    return membership


class OrganizationMemberResponse(BaseModel):
    membership_id: str
    user_id: str
    email: str
    role: str


@router.get(
    "/organizations/{organization_id}/members",
    response_model=list[OrganizationMemberResponse],
)
def list_organization_members(
    membership: Annotated[Membership, Depends(require_org_admin)],
    session: Annotated[Session, Depends(get_session)],
) -> list[OrganizationMemberResponse]:
    rows = session.execute(
        select(Membership, User.email)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == membership.organization_id)
        .order_by(User.email_normalized)
    ).all()
    return [
        OrganizationMemberResponse(
            membership_id=member.id,
            user_id=member.user_id,
            email=email,
            role=member.role,
        )
        for member, email in rows
    ]


class OrganizationResponse(BaseModel):
    id: str
    name: str
    role: str


@router.get("/organizations/{organization_id}", response_model=OrganizationResponse)
def get_organization(
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> OrganizationResponse:
    organization = session.get(Organization, membership.organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrganizationResponse(id=organization.id, name=organization.name, role=membership.role)
