from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.auth import organization_membership
from apps.api.db import get_session
from apps.api.rate_limits import rate_limit
from packages.security_core.models import AuditEvent, DomainAsset, Membership

router = APIRouter()
DOMAIN_CHALLENGE_PREFIX = "securelink-verification="
VERIFICATION_LIFETIME = timedelta(hours=24)
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RESERVED_SUFFIXES = {"example", "invalid", "localhost", "local", "test", "internal", "home"}


class DomainAssetRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)


class DomainAssetResponse(BaseModel):
    id: str
    hostname: str
    status: str
    dns_name: str | None = None
    dns_value: str | None = None
    created_at: datetime
    verified_at: datetime | None


def _admin_required(membership: Membership) -> None:
    if membership.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Owner or admin role required")


def _normalize_hostname(raw_hostname: str) -> str:
    candidate = raw_hostname.strip().rstrip(".")
    if not candidate or any(mark in candidate for mark in ("/", "\\", "@", ":", "*", "?", "#")):
        raise HTTPException(status_code=422, detail="Enter a domain name without a URL or wildcard")
    try:
        hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid domain name") from exc
    if len(hostname) > 253 or "." not in hostname:
        raise HTTPException(status_code=422, detail="Enter a fully qualified domain name")
    labels = hostname.split(".")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise HTTPException(status_code=422, detail="Invalid domain name")
    if labels[-1] in RESERVED_SUFFIXES:
        raise HTTPException(status_code=422, detail="Use a publicly registered domain name")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=422, detail="IP addresses cannot be added as domain assets")
    if labels[-1].isdecimal():
        raise HTTPException(status_code=422, detail="IP addresses cannot be added as domain assets")
    return hostname


def _challenge_token() -> str:
    return secrets.token_urlsafe(32)


def _challenge_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _response(asset: DomainAsset, token: str | None = None) -> DomainAssetResponse:
    return DomainAssetResponse(
        id=asset.id,
        hostname=asset.hostname,
        status=asset.status,
        dns_name=f"_securelink-verification.{asset.hostname}" if token else None,
        dns_value=f"{DOMAIN_CHALLENGE_PREFIX}{token}" if token else None,
        created_at=asset.created_at,
        verified_at=asset.verified_at,
    )


def _record_audit(
    session: Session, membership: Membership, action: str, asset: DomainAsset
) -> None:
    session.add(
        AuditEvent(
            organization_id=membership.organization_id,
            actor_user_id=membership.user_id,
            actor_type="user",
            action=action,
            target_type="domain_asset",
            target_id=asset.id,
            details=json.dumps({"hostname": asset.hostname}, separators=(",", ":")),
        )
    )


def _get_asset(session: Session, membership: Membership, asset_id: UUID) -> DomainAsset:
    asset = session.scalar(
        select(DomainAsset)
        .where(
            DomainAsset.id == str(asset_id),
            DomainAsset.organization_id == membership.organization_id,
        )
        .with_for_update()
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Domain asset not found")
    return asset


@router.post(
    "/organizations/{organization_id}/assets/domains",
    response_model=DomainAssetResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("domain_asset_create", 10, 3600))],
)
def create_domain_asset(
    payload: DomainAssetRequest,
    response: Response,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> DomainAssetResponse:
    response.headers["Cache-Control"] = "no-store"
    _admin_required(membership)
    hostname = _normalize_hostname(payload.hostname)
    if session.scalar(
        select(DomainAsset.id).where(
            DomainAsset.organization_id == membership.organization_id,
            DomainAsset.hostname == hostname,
        )
    ):
        raise HTTPException(status_code=409, detail="Domain asset already exists")

    token = _challenge_token()
    now = datetime.now(UTC)
    asset = DomainAsset(
        organization_id=membership.organization_id,
        hostname=hostname,
        status="pending",
        verification_token_hash=_challenge_hash(DOMAIN_CHALLENGE_PREFIX + token),
        verification_expires_at=now + VERIFICATION_LIFETIME,
        created_by_user_id=membership.user_id,
        created_at=now,
    )
    session.add(asset)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Domain asset already exists") from exc
    _record_audit(session, membership, "domain_asset.created", asset)
    session.commit()
    return _response(asset, token)


@router.get(
    "/organizations/{organization_id}/assets/domains",
    response_model=list[DomainAssetResponse],
)
def list_domain_assets(
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> list[DomainAssetResponse]:
    assets = session.scalars(
        select(DomainAsset)
        .where(DomainAsset.organization_id == membership.organization_id)
        .order_by(DomainAsset.created_at.desc(), DomainAsset.id)
    ).all()
    return [_response(asset) for asset in assets]


@router.post(
    "/organizations/{organization_id}/assets/domains/{asset_id}/challenge",
    response_model=DomainAssetResponse,
    dependencies=[Depends(rate_limit("domain_asset_challenge", 10, 3600))],
)
def renew_domain_challenge(
    asset_id: UUID,
    response: Response,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> DomainAssetResponse:
    response.headers["Cache-Control"] = "no-store"
    _admin_required(membership)
    asset = _get_asset(session, membership, asset_id)
    if asset.status == "verified":
        raise HTTPException(status_code=409, detail="Domain ownership is already verified")
    token = _challenge_token()
    asset.verification_token_hash = _challenge_hash(DOMAIN_CHALLENGE_PREFIX + token)
    asset.verification_expires_at = datetime.now(UTC) + VERIFICATION_LIFETIME
    _record_audit(session, membership, "domain_asset.challenge_renewed", asset)
    session.commit()
    return _response(asset, token)


@router.post(
    "/organizations/{organization_id}/assets/domains/{asset_id}/verify",
    response_model=DomainAssetResponse,
    dependencies=[Depends(rate_limit("domain_asset_verify", 10, 3600))],
)
def verify_domain_asset(
    asset_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> DomainAssetResponse:
    _admin_required(membership)
    asset = _get_asset(session, membership, asset_id)
    if asset.status == "verified":
        return _response(asset)
    now = datetime.now(UTC)
    expires_at = asset.verification_expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at is None or expires_at <= now:
        raise HTTPException(status_code=409, detail="Verification challenge expired; create a new challenge")

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 3
    try:
        records = resolver.resolve(f"_securelink-verification.{asset.hostname}", "TXT")
    except dns.exception.DNSException as exc:
        raise HTTPException(status_code=409, detail="Verification TXT record was not found") from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="DNS verification is temporarily unavailable") from exc

    expected_hash = asset.verification_token_hash or ""
    found = any(
        hmac.compare_digest(_challenge_hash(b"".join(record.strings).decode("utf-8", "replace")), expected_hash)
        for record in records
    )
    if not found:
        raise HTTPException(status_code=409, detail="Verification TXT record did not match")

    asset.status = "verified"
    asset.verified_at = now
    asset.verification_token_hash = None
    asset.verification_expires_at = None
    _record_audit(session, membership, "domain_asset.verified", asset)
    session.commit()
    return _response(asset)


@router.delete(
    "/organizations/{organization_id}/assets/domains/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_domain_asset(
    asset_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    _admin_required(membership)
    asset = _get_asset(session, membership, asset_id)
    _record_audit(session, membership, "domain_asset.deleted", asset)
    session.delete(asset)
    session.commit()
