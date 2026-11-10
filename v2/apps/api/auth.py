from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from urllib.parse import quote
from uuid import UUID, uuid4

import jwt
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db import get_session
from apps.api.emailer import email_delivery_configured, encrypt_action_token
from apps.api.mfa import (
    decrypt_secret,
    encrypt_secret,
    new_recovery_codes,
    new_totp_secret,
    recovery_code_hash,
    recovery_code_matches,
    verify_totp,
)
from apps.api.rate_limits import rate_limit
from packages.security_core.models import (
    AuditEvent,
    EmailActionToken,
    Membership,
    MFARecoveryCode,
    Organization,
    User,
)

router = APIRouter()
bearer = HTTPBearer(auto_error=False)
password_hash = PasswordHash.recommended()
dummy_password_hash = password_hash.hash("invalid-login-dummy-password")
email_pattern = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
token_issuer = "securelink-v2"
token_audience = "securelink-v2-api"
access_token_minutes = 15
verification_lifetime = timedelta(hours=24)
reset_lifetime = timedelta(hours=1)
invitation_lifetime = timedelta(hours=48)
generic_email_message = "If the address is eligible, an email will be sent with next steps."


class RegistrationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    organization_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=32)


class MFACodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class MFADisableRequest(MFACodeRequest):
    password: str = Field(min_length=1, max_length=128)


class MFAEnrollmentResponse(BaseModel):
    secret: str
    otpauth_uri: str
    expires_in: int = 900


class MFAStatusResponse(BaseModel):
    enabled: bool


class EmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class ActionTokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=256)


class InvitationAcceptRequest(ActionTokenRequest):
    password: str | None = Field(default=None, min_length=12, max_length=128)


class PasswordResetRequest(ActionTokenRequest):
    new_password: str = Field(min_length=12, max_length=128)


class MessageResponse(BaseModel):
    message: str


class InvitationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: Literal["owner", "admin", "analyst", "viewer"]


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


def _mfa_key() -> str:
    key = get_settings().mfa_encryption_key
    if not key or "replace-with" in key:
        raise HTTPException(status_code=503, detail="MFA is not configured")
    try:
        Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError, TypeError) as exc:
        raise HTTPException(status_code=503, detail="MFA is not configured") from exc
    return key


def _valid_mfa_code(session: Session, user: User, code: str | None) -> bool:
    if not user.mfa_enabled or user.mfa_secret_ciphertext is None or not code:
        return False
    try:
        secret = decrypt_secret(user.mfa_secret_ciphertext, _mfa_key())
    except ValueError:
        return False
    if verify_totp(secret, code):
        return True
    try:
        digest = recovery_code_hash(code)
    except UnicodeEncodeError:
        return False
    recovery = session.scalar(
        select(MFARecoveryCode)
        .where(
            MFARecoveryCode.user_id == user.id,
            MFARecoveryCode.code_hash == digest,
            MFARecoveryCode.consumed_at.is_(None),
        )
        .with_for_update()
    )
    if recovery is None or not recovery_code_matches(code, recovery.code_hash):
        return False
    recovery.consumed_at = datetime.now(UTC)
    return True


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
) -> None:
    now = datetime.now(UTC)
    session.execute(
        update(EmailActionToken)
        .where(
            EmailActionToken.user_id == user.id,
            EmailActionToken.purpose == purpose,
            EmailActionToken.consumed_at.is_(None),
        )
        .values(consumed_at=now, delivery_state="cancelled", delivery_ciphertext=None)
    )
    token = secrets.token_urlsafe(32)
    session.add(
        EmailActionToken(
            user_id=user.id,
            purpose=purpose,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=now + lifetime,
            delivery_ciphertext=encrypt_action_token(token),
            delivery_state="pending",
            next_delivery_at=now,
        )
    )


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
    try:
        with session.begin():
            session.add_all([user, organization])
            session.flush()
            session.add(
                Membership(user_id=user.id, organization_id=organization.id, role="owner")
            )
            _new_action_token(session, user, "verify_email", verification_lifetime)
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
    with session.begin():
        user = session.scalar(select(User).where(User.email_normalized == normalized_email))
        if user is not None and user.is_active and not user.email_verified:
            _new_action_token(session, user, "verify_email", verification_lifetime)
    return MessageResponse(message=generic_email_message)


@router.post(
    "/auth/verify-email",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("verify_email", 10, 3600))],
)
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
        select(User).where(User.email_normalized == payload.email.strip().casefold()).with_for_update()
    )
    stored_hash = user.password_hash if user is not None else dummy_password_hash
    password_matches = password_hash.verify(payload.password, stored_hash)
    if user is None or not user.is_active or not user.email_verified or not password_matches:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.mfa_enabled and not _valid_mfa_code(session, user, payload.mfa_code):
        session.rollback()
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
    with session.begin():
        user = session.scalar(select(User).where(User.email_normalized == normalized_email))
        if user is not None and user.is_active and user.email_verified:
            _new_action_token(session, user, "reset_password", reset_lifetime)
    return MessageResponse(message=generic_email_message)


@router.post(
    "/auth/password/reset",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("password_reset", 5, 3600))],
)
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


@router.get("/auth/mfa", response_model=MFAStatusResponse)
def mfa_status(
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> MFAStatusResponse:
    user = session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return MFAStatusResponse(enabled=user.mfa_enabled)


@router.post(
    "/auth/mfa/enrollment", response_model=MFAEnrollmentResponse,
    dependencies=[Depends(rate_limit("mfa_enrollment", 5, 3600))],
)
def start_mfa_enrollment(
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> MFAEnrollmentResponse:
    key = _mfa_key()
    user = session.get(User, principal.user_id, with_for_update=True)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = new_totp_secret()
    user.mfa_secret_ciphertext = encrypt_secret(secret, key)
    user.mfa_enrollment_expires_at = datetime.now(UTC) + timedelta(minutes=15)
    session.commit()
    label = quote(f"SecureLink:{user.email}")
    return MFAEnrollmentResponse(
        secret=secret,
        otpauth_uri=f"otpauth://totp/{label}?secret={secret}&issuer=SecureLink&digits=6&period=30",
    )


@router.post("/auth/mfa/confirm", dependencies=[Depends(rate_limit("mfa_confirm", 5, 300))])
def confirm_mfa_enrollment(
    payload: MFACodeRequest,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, list[str]]:
    user = session.get(User, principal.user_id, with_for_update=True)
    now = datetime.now(UTC)
    enrollment_expires_at = user.mfa_enrollment_expires_at if user is not None else None
    if enrollment_expires_at is not None and enrollment_expires_at.tzinfo is None:
        enrollment_expires_at = enrollment_expires_at.replace(tzinfo=UTC)
    if (
        user is None
        or user.mfa_enabled
        or user.mfa_secret_ciphertext is None
        or user.mfa_enrollment_expires_at is None
        or enrollment_expires_at <= now
    ):
        raise HTTPException(status_code=400, detail="MFA enrollment is missing or expired")
    try:
        secret = decrypt_secret(user.mfa_secret_ciphertext, _mfa_key())
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="MFA enrollment cannot be verified") from exc
    if not verify_totp(secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    codes = new_recovery_codes()
    user.mfa_enabled = True
    user.mfa_enrollment_expires_at = None
    session.add_all(
        MFARecoveryCode(user_id=user.id, code_hash=recovery_code_hash(code)) for code in codes
    )
    membership = session.scalar(
        select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at).limit(1)
    )
    session.add(AuditEvent(
        organization_id=membership.organization_id if membership else None,
        actor_user_id=user.id, actor_type="user", action="user.mfa_enabled",
        target_type="user", target_id=user.id, details="{}",
    ))
    session.commit()
    return {"recovery_codes": codes}


@router.post(
    "/auth/mfa/disable", response_model=MFAStatusResponse,
    dependencies=[Depends(rate_limit("mfa_disable", 5, 300))],
)
def disable_mfa(
    payload: MFADisableRequest,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> MFAStatusResponse:
    user = session.get(User, principal.user_id, with_for_update=True)
    if user is None or not user.mfa_enabled or not password_hash.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="MFA could not be disabled")
    if not _valid_mfa_code(session, user, payload.code):
        session.rollback()
        raise HTTPException(status_code=400, detail="MFA could not be disabled")
    user.mfa_enabled = False
    user.mfa_secret_ciphertext = None
    user.mfa_enrollment_expires_at = None
    user.token_version += 1
    session.execute(
        update(MFARecoveryCode)
        .where(MFARecoveryCode.user_id == user.id)
        .values(consumed_at=datetime.now(UTC))
    )
    membership = session.scalar(
        select(Membership).where(Membership.user_id == user.id).order_by(Membership.created_at).limit(1)
    )
    session.add(AuditEvent(
        organization_id=membership.organization_id if membership else None,
        actor_user_id=user.id, actor_type="user", action="user.mfa_disabled",
        target_type="user", target_id=user.id, details="{}",
    ))
    session.commit()
    return MFAStatusResponse(enabled=False)



@router.post("/auth/logout", status_code=204)
def logout(
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    user = session.get(User, principal.user_id, with_for_update=True)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    membership = session.scalar(
        select(Membership)
        .where(Membership.user_id == user.id)
        .order_by(Membership.created_at, Membership.id)
        .limit(1)
    )
    user.token_version += 1
    session.add(
        AuditEvent(
            organization_id=membership.organization_id if membership else None,
            actor_user_id=user.id,
            actor_type="user",
            action="user.logout",
            target_type="user",
            target_id=user.id,
            details="{}",
        )
    )
    session.commit()


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


class MembershipRoleUpdate(BaseModel):
    role: Literal["owner", "admin", "analyst", "viewer"]


class MembershipMutationResponse(BaseModel):
    membership_id: str
    user_id: str
    role: str


def _target_membership(
    session: Session,
    organization_id: str,
    membership_id: str,
) -> Membership:
    organization = session.get(Organization, organization_id, with_for_update=True)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    target = session.scalar(
        select(Membership)
        .where(
            Membership.id == membership_id,
            Membership.organization_id == organization_id,
        )
        .with_for_update()
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Member not found")
    return target


def _ensure_admin_can_manage(actor: Membership, target: Membership, new_role: str | None = None) -> None:
    if actor.role == "owner":
        return
    if target.role in {"owner", "admin"} or new_role in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only an owner can manage owners or admins")


def _owner_count(session: Session, organization_id: str) -> int:
    return session.scalar(
        select(func.count())
        .select_from(Membership)
        .where(
            Membership.organization_id == organization_id,
            Membership.role == "owner",
        )
    ) or 0


@router.patch(
    "/organizations/{organization_id}/members/{membership_id}",
    response_model=MembershipMutationResponse,
)
def update_organization_member_role(
    organization_id: str,
    membership_id: str,
    payload: MembershipRoleUpdate,
    actor: Annotated[Membership, Depends(require_org_admin)],
    session: Annotated[Session, Depends(get_session)],
) -> MembershipMutationResponse:
    target = _target_membership(session, actor.organization_id, membership_id)
    _ensure_admin_can_manage(actor, target, payload.role)
    if target.role == "owner" and payload.role != "owner" and _owner_count(session, actor.organization_id) <= 1:
        raise HTTPException(status_code=409, detail="The organization must retain an owner")
    previous_role = target.role
    if previous_role != payload.role:
        target.role = payload.role
        session.add(
            AuditEvent(
                organization_id=actor.organization_id,
                actor_user_id=actor.user_id,
                actor_type="user",
                action="membership.role_changed",
                target_type="membership",
                target_id=target.id,
                details=json.dumps({"from": previous_role, "to": payload.role}, separators=(",", ":")),
            )
        )
        session.commit()
    return MembershipMutationResponse(
        membership_id=target.id,
        user_id=target.user_id,
        role=target.role,
    )


@router.delete(
    "/organizations/{organization_id}/members/{membership_id}",
    status_code=204,
)
def remove_organization_member(
    organization_id: str,
    membership_id: str,
    actor: Annotated[Membership, Depends(require_org_admin)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    target = _target_membership(session, actor.organization_id, membership_id)
    _ensure_admin_can_manage(actor, target)
    if target.role == "owner" and _owner_count(session, actor.organization_id) <= 1:
        raise HTTPException(status_code=409, detail="The organization must retain an owner")
    session.add(
        AuditEvent(
            organization_id=actor.organization_id,
            actor_user_id=actor.user_id,
            actor_type="user",
            action="membership.removed",
            target_type="membership",
            target_id=target.id,
            details=json.dumps({"role": target.role}, separators=(",", ":")),
        )
    )
    session.delete(target)
    session.commit()




@router.post(
    "/organizations/{organization_id}/invitations",
    response_model=MessageResponse,
    status_code=202,
    dependencies=[Depends(rate_limit("member_invite", 10, 3600))],
)
def invite_organization_member(
    organization_id: str,
    payload: InvitationRequest,
    actor: Annotated[Membership, Depends(require_org_admin)],
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    _require_email_delivery()
    email = payload.email.strip()
    if not email_pattern.fullmatch(email):
        raise HTTPException(status_code=422, detail="Invalid email")
    if actor.role == "admin" and payload.role in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Only an owner can invite owners or admins")

    session.get(Organization, actor.organization_id, with_for_update=True)
    invited_user = session.scalar(
        select(User).where(User.email_normalized == email.casefold())
    )
    response = MessageResponse(message="If the account is eligible, an invitation will be sent.")
    if invited_user is None:
        invited_user = User(
            email=email,
            email_normalized=email.casefold(),
            password_hash=password_hash.hash(secrets.token_urlsafe(48)),
            email_verified=False,
            invitation_setup_required=True,
        )
        session.add(invited_user)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            return response
    elif (
        not invited_user.is_active
        or (not invited_user.email_verified and not invited_user.invitation_setup_required)
    ):
        return response
    existing = session.scalar(
        select(Membership.id).where(
            Membership.organization_id == actor.organization_id,
            Membership.user_id == invited_user.id,
        )
    )
    if existing is not None:
        return response

    now = datetime.now(UTC)
    session.execute(
        update(EmailActionToken)
        .where(
            EmailActionToken.user_id == invited_user.id,
            EmailActionToken.organization_id == actor.organization_id,
            EmailActionToken.purpose == "invite_member",
            EmailActionToken.consumed_at.is_(None),
        )
        .values(consumed_at=now, delivery_state="cancelled", delivery_ciphertext=None)
    )
    raw_token = secrets.token_urlsafe(32)
    session.add(
        EmailActionToken(
            user_id=invited_user.id,
            organization_id=actor.organization_id,
            requested_role=payload.role,
            purpose="invite_member",
            token_hash=hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
            expires_at=now + invitation_lifetime,
            delivery_ciphertext=encrypt_action_token(raw_token),
            delivery_state="pending",
            next_delivery_at=now,
        )
    )
    session.add(
        AuditEvent(
            organization_id=actor.organization_id,
            actor_user_id=actor.user_id,
            actor_type="user",
            action="membership.invitation_created",
            target_type="user",
            target_id=invited_user.id,
            details=json.dumps({"role": payload.role}, separators=(",", ":")),
        )
    )
    session.commit()
    return response


@router.post(
    "/auth/invitations/accept",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("invitation_accept", 10, 3600))],
)
def accept_organization_invitation(
    payload: InvitationAcceptRequest,
    session: Annotated[Session, Depends(get_session)],
) -> MessageResponse:
    with session.begin():
        digest = hashlib.sha256(payload.token.encode("utf-8")).hexdigest()
        organization_id = session.scalar(
            select(EmailActionToken.organization_id).where(
                EmailActionToken.token_hash == digest,
                EmailActionToken.purpose == "invite_member",
                EmailActionToken.consumed_at.is_(None),
                EmailActionToken.expires_at > func.now(),
            )
        )
        if organization_id is None:
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")
        organization = session.get(Organization, organization_id, with_for_update=True)
        if organization is None:
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")
        action_token, user = _consume_action_token(session, payload.token, "invite_member")
        role = action_token.requested_role
        if action_token.organization_id != organization_id or role is None:
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")
        if user.invitation_setup_required:
            if payload.password is None:
                raise HTTPException(
                    status_code=400,
                    detail="Choose a password to finish setting up your invited account",
                )
            user.password_hash = password_hash.hash(payload.password)
            user.email_verified = True
            user.invitation_setup_required = False
        elif not user.email_verified:
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")
        existing = session.scalar(
            select(Membership.id).where(
                Membership.organization_id == organization_id,
                Membership.user_id == user.id,
            )
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="Already a member of this organization")
        membership = Membership(
            organization_id=organization_id,
            user_id=user.id,
            role=role,
        )
        session.add(membership)
        session.flush()
        session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=user.id,
                actor_type="user",
                action="membership.invitation_accepted",
                target_type="membership",
                target_id=membership.id,
                details=json.dumps({"role": role}, separators=(",", ":")),
            )
        )
    return MessageResponse(message="Invitation accepted")


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


@router.get("/auth/organizations", response_model=list[OrganizationResponse])
def list_my_organizations(
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
    response: Response,
) -> list[OrganizationResponse]:
    response.headers["Cache-Control"] = "no-store"
    rows = session.execute(
        select(Organization.id, Organization.name, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == principal.user_id)
        .order_by(Organization.name, Organization.id)
    ).all()
    return [OrganizationResponse(id=org_id, name=name, role=role) for org_id, name, role in rows]


@router.get("/organizations/{organization_id}", response_model=OrganizationResponse)
def get_organization(
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> OrganizationResponse:
    organization = session.get(Organization, membership.organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrganizationResponse(id=organization.id, name=organization.name, role=membership.role)
