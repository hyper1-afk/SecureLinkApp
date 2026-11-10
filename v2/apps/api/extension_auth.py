from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from urllib.parse import urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.auth import Principal, bearer, current_principal
from apps.api.config import get_settings
from apps.api.db import get_session
from apps.api.rate_limits import rate_limit
from apps.api.scanning import ScanResponse, _create_scan, _read_scan_url
from packages.security_core.models import (
    AuditEvent,
    ExtensionAuthorizationCode,
    ExtensionSession,
    Membership,
    Organization,
    User,
)

router = APIRouter()
CLIENT_ID = "securelink-chrome-extension"
CODE_LIFETIME = timedelta(minutes=3)
SESSION_LIFETIME = timedelta(hours=12)


class OAuthOrganization(BaseModel):
    id: str
    name: str
    role: str


class OAuthOrganizations(BaseModel):
    organizations: list[OAuthOrganization]


class AuthorizationRequest(BaseModel):
    client_id: Literal["securelink-chrome-extension"]
    redirect_uri: str = Field(min_length=1, max_length=512)
    organization_id: str
    state: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    code_challenge: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    code_challenge_method: Literal["S256"]


class AuthorizationResponse(BaseModel):
    redirect_url: str


class TokenRequest(BaseModel):
    grant_type: Literal["authorization_code"]
    client_id: Literal["securelink-chrome-extension"]
    code: str = Field(min_length=32, max_length=128)
    redirect_uri: str = Field(min_length=1, max_length=512)
    code_verifier: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$")


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int = int(SESSION_LIFETIME.total_seconds())
    scope: Literal["url_scan"] = "url_scan"
    organization_id: str


class ExtensionSessionSummary(BaseModel):
    id: str
    organization_id: str
    organization_name: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


@dataclass(frozen=True)
class ExtensionPrincipal:
    session_id: str
    user_id: str
    organization_id: str


def _allowed_redirect(uri: str) -> bool:
    configured = {
        item.strip()
        for item in get_settings().extension_redirect_uris.split(",")
        if item.strip()
    }
    return uri in configured


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _audit(
    session: Session,
    organization_id: str,
    user_id: str,
    action: str,
    target_type: str,
    target_id: str,
) -> None:
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user_id,
            actor_type="user",
            action=action,
            target_type=target_type,
            target_id=target_id,
            details="{}",
        )
    )


@router.get("/extension/oauth/organizations", response_model=OAuthOrganizations)
def list_authorizable_organizations(
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> OAuthOrganizations:
    response.headers["Cache-Control"] = "no-store"
    rows = session.execute(
        select(Organization.id, Organization.name, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(
            Membership.user_id == principal.user_id,
            Membership.role.in_(("owner", "admin", "analyst")),
        )
        .order_by(Membership.created_at, Membership.id)
    ).all()
    organizations = [
        OAuthOrganization(id=organization_id, name=name, role=role)
        for organization_id, name, role in rows
    ]
    return OAuthOrganizations(organizations=organizations)


@router.post(
    "/extension/oauth/authorize",
    response_model=AuthorizationResponse,
    dependencies=[Depends(rate_limit("extension_authorize", 10, 60))],
)
def authorize_extension(
    payload: AuthorizationRequest,
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> AuthorizationResponse:
    response.headers["Cache-Control"] = "no-store"
    if not _allowed_redirect(payload.redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid extension redirect URI")
    try:
        organization_id = str(UUID(payload.organization_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Organization not found") from exc
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == principal.user_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    if membership.role not in {"owner", "admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst role or higher is required")
    user = session.get(User, principal.user_id)
    if user is None or not user.is_active or not user.email_verified:
        raise HTTPException(status_code=401, detail="Authentication required")

    authorization_code = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    row = ExtensionAuthorizationCode(
        code_hash=_hash_secret(authorization_code),
        client_id=CLIENT_ID,
        redirect_uri=payload.redirect_uri,
        code_challenge=payload.code_challenge,
        user_id=user.id,
        organization_id=organization_id,
        token_version=user.token_version,
        expires_at=now + CODE_LIFETIME,
    )
    session.add(row)
    session.flush()
    _audit(
        session,
        organization_id,
        user.id,
        "extension.authorization_code_issued",
        "extension_authorization_code",
        row.id,
    )
    session.commit()
    return AuthorizationResponse(
        redirect_url=(
            payload.redirect_uri
            + "?"
            + urlencode({"code": authorization_code, "state": payload.state})
        )
    )


@router.post(
    "/extension/oauth/token",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("extension_token", 60, 60))],
)
def exchange_authorization_code(
    payload: TokenRequest,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
) -> TokenResponse:
    response.headers["Cache-Control"] = "no-store"
    if not _allowed_redirect(payload.redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    now = datetime.now(UTC)
    row = session.scalar(
        select(ExtensionAuthorizationCode)
        .where(
            ExtensionAuthorizationCode.code_hash == _hash_secret(payload.code),
            ExtensionAuthorizationCode.client_id == CLIENT_ID,
            ExtensionAuthorizationCode.redirect_uri == payload.redirect_uri,
            ExtensionAuthorizationCode.consumed_at.is_(None),
            ExtensionAuthorizationCode.expires_at > now,
        )
        .with_for_update()
    )
    if row is None:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    row.consumed_at = now
    if not secrets.compare_digest(row.code_challenge, _pkce_challenge(payload.code_verifier)):
        session.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")
    user = session.get(User, row.user_id)
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == row.organization_id,
            Membership.user_id == row.user_id,
        )
    )
    if (
        user is None
        or not user.is_active
        or user.token_version != row.token_version
        or membership is None
        or membership.role not in {"owner", "admin", "analyst"}
    ):
        session.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    access_token = secrets.token_urlsafe(48)
    extension_session = ExtensionSession(
        token_hash=_hash_secret(access_token),
        user_id=user.id,
        organization_id=row.organization_id,
        token_version=user.token_version,
        expires_at=now + SESSION_LIFETIME,
    )
    session.add(extension_session)
    _audit(
        session,
        row.organization_id,
        user.id,
        "extension.session_created",
        "extension_session",
        extension_session.id,
    )
    session.commit()
    return TokenResponse(access_token=access_token, organization_id=row.organization_id)


@router.get("/extension/oauth/sessions", response_model=list[ExtensionSessionSummary])
def list_extension_sessions(
    response: Response,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> list[ExtensionSessionSummary]:
    response.headers["Cache-Control"] = "no-store"
    rows = session.execute(
        select(ExtensionSession, Organization.name)
        .join(Organization, Organization.id == ExtensionSession.organization_id)
        .where(ExtensionSession.user_id == principal.user_id)
        .order_by(ExtensionSession.created_at.desc(), ExtensionSession.id)
    ).all()
    return [
        ExtensionSessionSummary(
            id=extension_session.id,
            organization_id=extension_session.organization_id,
            organization_name=organization_name,
            created_at=extension_session.created_at,
            expires_at=extension_session.expires_at,
            revoked_at=extension_session.revoked_at,
        )
        for extension_session, organization_name in rows
    ]


@router.delete("/extension/oauth/sessions/{session_id}", status_code=204)
def revoke_extension_session_from_account(
    session_id: UUID,
    principal: Annotated[Principal, Depends(current_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    extension_session = session.scalar(
        select(ExtensionSession)
        .where(
            ExtensionSession.id == str(session_id),
            ExtensionSession.user_id == principal.user_id,
        )
        .with_for_update()
    )
    if extension_session is None:
        raise HTTPException(status_code=404, detail="Extension session not found")
    if extension_session.revoked_at is None:
        extension_session.revoked_at = datetime.now(UTC)
        _audit(
            session,
            extension_session.organization_id,
            principal.user_id,
            "extension.session_revoked",
            "extension_session",
            extension_session.id,
        )
        session.commit()


def extension_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Annotated[Session, Depends(get_session)],
) -> ExtensionPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Extension authorization required")
    now = datetime.now(UTC)
    extension_session = session.scalar(
        select(ExtensionSession).where(
            ExtensionSession.token_hash == _hash_secret(credentials.credentials),
            ExtensionSession.revoked_at.is_(None),
            ExtensionSession.expires_at > now,
        )
    )
    if extension_session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired extension authorization")
    user = session.get(User, extension_session.user_id)
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == extension_session.organization_id,
            Membership.user_id == extension_session.user_id,
        )
    )
    if (
        user is None
        or not user.is_active
        or user.token_version != extension_session.token_version
        or membership is None
    ):
        raise HTTPException(status_code=401, detail="Invalid or expired extension authorization")
    if membership.role not in {"owner", "admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst role or higher is required")
    return ExtensionPrincipal(
        session_id=extension_session.id,
        user_id=extension_session.user_id,
        organization_id=extension_session.organization_id,
    )


@router.post(
    "/extension/v1/scans",
    response_model=ScanResponse,
    status_code=201,
    dependencies=[Depends(rate_limit("url_scan", 20, 60))],
)
async def create_extension_scan(
    request: Request,
    principal: Annotated[ExtensionPrincipal, Depends(extension_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> ScanResponse:
    raw_url = await _read_scan_url(request)
    return await _create_scan(raw_url, principal.organization_id, principal.user_id, session)


@router.post("/extension/oauth/revoke", status_code=204)
def revoke_extension_session(
    principal: Annotated[ExtensionPrincipal, Depends(extension_principal)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    extension_session = session.get(ExtensionSession, principal.session_id, with_for_update=True)
    if extension_session is None or extension_session.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Invalid extension authorization")
    now = datetime.now(UTC)
    extension_session.revoked_at = now
    _audit(
        session,
        principal.organization_id,
        principal.user_id,
        "extension.session_revoked",
        "extension_session",
        extension_session.id,
    )
    session.commit()
