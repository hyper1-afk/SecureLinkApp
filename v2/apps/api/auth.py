from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db import get_session
from packages.security_core.models import AuditEvent, Membership, Organization, User

router = APIRouter()
bearer = HTTPBearer(auto_error=False)
password_hash = PasswordHash.recommended()
dummy_password_hash = password_hash.hash("invalid-login-dummy-password")
email_pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
token_issuer = "securelink-v2"
token_audience = "securelink-v2-api"
access_token_minutes = 15


class RegistrationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    organization_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)


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


def _issue_token(user_id: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": user_id,
            "iss": token_issuer,
            "aud": token_audience,
            "iat": now,
            "exp": now + timedelta(minutes=access_token_minutes),
            "jti": str(uuid4()),
        },
        _secret_key(),
        algorithm="HS256",
    )


def _token_response(user_id: str, organization_id: str) -> TokenResponse:
    return TokenResponse(access_token=_issue_token(user_id), organization_id=organization_id)


@router.post("/auth/register", response_model=TokenResponse, status_code=201)
def register(
    payload: RegistrationRequest,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    _secret_key()
    email = payload.email.strip()
    organization_name = payload.organization_name.strip()
    if not email_pattern.fullmatch(email) or not organization_name:
        raise HTTPException(status_code=422, detail="Invalid email or organization name")

    user = User(
        email=email,
        email_normalized=email.casefold(),
        password_hash=password_hash.hash(payload.password),
    )
    organization = Organization(name=organization_name)
    try:
        with session.begin():
            session.add_all([user, organization])
            session.flush()
            session.add(
                Membership(user_id=user.id, organization_id=organization.id, role="owner")
            )
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
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="An account with that email already exists") from exc

    return _token_response(user.id, organization.id)


@router.post("/auth/login", response_model=TokenResponse)
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
    if user is None or not user.is_active or not password_matches:
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
    return _token_response(user.id, membership.organization_id)


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
            options={"require": ["sub", "exp", "iat", "iss", "aud", "jti"]},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    try:
        user_id = str(UUID(claims["sub"]))
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Account is inactive",
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


def record_audit_event(
    session: Session,
    *,
    organization_id: str,
    actor_user_id: str,
    action: str,
    target_type: str,
    target_id: str | None,
    details: dict[str, object] | None = None,
) -> None:
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            actor_type="user",
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=json.dumps(details or {}, sort_keys=True, separators=(",", ":")),
        )
    )
