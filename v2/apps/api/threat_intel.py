from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.auth import organization_membership
from apps.api.db import get_session
from apps.api.rate_limits import rate_limit
from packages.security_core.models import AuditEvent, Membership, ThreatIndicator

router = APIRouter()
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class IndicatorCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    note: str | None = Field(default=None, max_length=240)


class IndicatorResponse(BaseModel):
    id: str
    hostname: str
    source: str
    note: str | None
    created_at: datetime


def _admin(membership: Membership) -> None:
    if membership.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Owner or admin role required")


def _hostname(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or any(char in value for char in "/\\:@?#"):
        raise HTTPException(status_code=422, detail="Enter a hostname, not a URL or IP address")
    try:
        result = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise HTTPException(status_code=422, detail="Invalid hostname") from exc
    try:
        ipaddress.ip_address(result)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=422, detail="IP addresses are not supported as indicators")
    if len(result) > 253 or "." not in result or any(not LABEL.fullmatch(part) for part in result.split(".")):
        raise HTTPException(status_code=422, detail="Invalid hostname")
    return result


@router.post(
    "/organizations/{organization_id}/threat-indicators",
    response_model=IndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("indicator_create", 50, 3600))],
)
def create_indicator(
    payload: IndicatorCreate,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> IndicatorResponse:
    _admin(membership)
    hostname = _hostname(payload.hostname)
    indicator = ThreatIndicator(
        organization_id=membership.organization_id,
        hostname=hostname,
        note=payload.note.strip() if payload.note and payload.note.strip() else None,
        created_by_user_id=membership.user_id,
    )
    session.add(indicator)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Hostname indicator already exists") from exc
    session.add(AuditEvent(
        organization_id=membership.organization_id,
        actor_user_id=membership.user_id,
        actor_type="user",
        action="threat_indicator.created",
        target_type="threat_indicator",
        target_id=indicator.id,
        details=json.dumps({"hostname": hostname}, separators=(",", ":")),
    ))
    session.commit()
    return IndicatorResponse.model_validate(indicator, from_attributes=True)


@router.get("/organizations/{organization_id}/threat-indicators", response_model=list[IndicatorResponse])
def list_indicators(
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> list[IndicatorResponse]:
    rows = session.scalars(
        select(ThreatIndicator)
        .where(ThreatIndicator.organization_id == membership.organization_id)
        .order_by(ThreatIndicator.created_at.desc(), ThreatIndicator.id)
        .limit(1000)
    ).all()
    return [IndicatorResponse.model_validate(row, from_attributes=True) for row in rows]


@router.delete(
    "/organizations/{organization_id}/threat-indicators/{indicator_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit("indicator_delete", 50, 3600))],
)
def delete_indicator(
    indicator_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> None:
    _admin(membership)
    indicator = session.scalar(select(ThreatIndicator).where(
        ThreatIndicator.id == str(indicator_id),
        ThreatIndicator.organization_id == membership.organization_id,
    ))
    if indicator is None:
        raise HTTPException(status_code=404, detail="Threat indicator not found")
    session.add(AuditEvent(
        organization_id=membership.organization_id,
        actor_user_id=membership.user_id,
        actor_type="user",
        action="threat_indicator.deleted",
        target_type="threat_indicator",
        target_id=indicator.id,
        details=json.dumps({"hostname": indicator.hostname}, separators=(",", ":")),
    ))
    session.delete(indicator)
    session.commit()
