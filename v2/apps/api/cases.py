from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.auth import organization_membership
from apps.api.db import get_session
from packages.security_core.models import (
    AuditEvent,
    CaseFinding,
    Finding,
    IncidentCase,
    Membership,
    UrlScan,
)

router = APIRouter()
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
CASE_TRANSITIONS = {
    "open": {"investigating", "resolved", "false_positive"},
    "investigating": {"open", "awaiting_approval", "resolved", "false_positive"},
    "awaiting_approval": {"open", "investigating", "resolved", "false_positive"},
    "resolved": {"investigating"},
    "false_positive": {"investigating"},
}


class CaseStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "awaiting_approval", "resolved", "false_positive"]


class CaseFindingResponse(BaseModel):
    id: str
    detector_code: str
    severity: str
    title: str
    description: str
    evidence_id: str


class CaseResponse(BaseModel):
    id: str
    scan_id: str
    status: str
    severity: str
    title: str
    summary: str
    hostname: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    findings: list[CaseFindingResponse]


def _require_analyst(membership: Membership) -> None:
    if membership.role not in {"owner", "admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst role or higher is required")


def _case_response(
    case: IncidentCase, hostname: str, findings: list[Finding]
) -> CaseResponse:
    return CaseResponse(
        id=case.id,
        scan_id=case.scan_id,
        status=case.status,
        severity=case.severity,
        title=case.title,
        summary=case.summary,
        hostname=hostname,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        findings=[
            CaseFindingResponse(
                id=finding.id,
                detector_code=finding.detector_code,
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                evidence_id=finding.evidence_id,
            )
            for finding in findings
        ],
    )


def _findings_for_case(session: Session, case: IncidentCase) -> list[Finding]:
    return session.scalars(
        select(Finding)
        .join(CaseFinding, CaseFinding.finding_id == Finding.id)
        .where(
            CaseFinding.case_id == case.id,
            CaseFinding.organization_id == case.organization_id,
            Finding.organization_id == case.organization_id,
        )
        .order_by(Finding.created_at, Finding.detector_code)
    ).all()


def _case_scan(session: Session, case: IncidentCase) -> UrlScan:
    scan = session.scalar(
        select(UrlScan).where(
            UrlScan.id == case.scan_id,
            UrlScan.organization_id == case.organization_id,
        )
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return scan


@router.post(
    "/organizations/{organization_id}/cases/from-scan/{scan_id}",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_case_from_scan(
    organization_id: str,
    scan_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
    response: Response,
) -> CaseResponse:
    _require_analyst(membership)
    scan = session.scalar(
        select(UrlScan).where(
            UrlScan.id == str(scan_id),
            UrlScan.organization_id == membership.organization_id,
        )
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    existing = session.scalar(
        select(IncidentCase).where(
            IncidentCase.scan_id == scan.id,
            IncidentCase.organization_id == membership.organization_id,
        )
    )
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        return _case_response(existing, scan.hostname, _findings_for_case(session, existing))

    findings = session.scalars(
        select(Finding)
        .where(
            Finding.scan_id == scan.id,
            Finding.organization_id == membership.organization_id,
        )
        .order_by(Finding.created_at, Finding.detector_code)
    ).all()
    if not findings:
        raise HTTPException(status_code=409, detail="Scan has no findings to open as a case")

    severity = min((finding.severity for finding in findings), key=SEVERITY_RANK.__getitem__)
    now = datetime.now(UTC)
    case = IncidentCase(
        organization_id=membership.organization_id,
        scan_id=scan.id,
        created_by_user_id=membership.user_id,
        status="open",
        severity=severity,
        title=f"Review URL signals for {scan.hostname}",
        summary=(
            f"{len(findings)} finding(s) were produced by the passive URL hygiene check. "
            "Review the evidence; this is not a safety verdict."
        ),
        created_at=now,
        updated_at=now,
    )
    session.add(case)
    session.flush()
    session.add_all(
        CaseFinding(
            organization_id=membership.organization_id,
            case_id=case.id,
            finding_id=finding.id,
        )
        for finding in findings
    )
    session.add(
        AuditEvent(
            organization_id=membership.organization_id,
            actor_user_id=membership.user_id,
            actor_type="user",
            action="case.created_from_scan",
            target_type="incident_case",
            target_id=case.id,
            details=json.dumps(
                {"scan_id": scan.id, "finding_count": len(findings)}, separators=(",", ":")
            ),
        )
    )
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        existing = session.scalar(
            select(IncidentCase).where(
                IncidentCase.scan_id == scan.id,
                IncidentCase.organization_id == membership.organization_id,
            )
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="Findings are already linked to a case") from exc
        response.status_code = status.HTTP_200_OK
        return _case_response(existing, scan.hostname, _findings_for_case(session, existing))
    return _case_response(case, scan.hostname, findings)


@router.get("/organizations/{organization_id}/cases", response_model=list[CaseResponse])
def list_cases(
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[CaseResponse]:
    cases = session.scalars(
        select(IncidentCase)
        .where(IncidentCase.organization_id == membership.organization_id)
        .order_by(IncidentCase.updated_at.desc(), IncidentCase.id)
        .limit(limit)
    ).all()
    result = []
    for case in cases:
        scan = _case_scan(session, case)
        result.append(_case_response(case, scan.hostname, _findings_for_case(session, case)))
    return result


@router.get(
    "/organizations/{organization_id}/cases/{case_id}",
    response_model=CaseResponse,
)
def get_case(
    case_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> CaseResponse:
    case = session.scalar(
        select(IncidentCase).where(
            IncidentCase.id == str(case_id),
            IncidentCase.organization_id == membership.organization_id,
        )
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    scan = _case_scan(session, case)
    return _case_response(case, scan.hostname, _findings_for_case(session, case))


@router.patch(
    "/organizations/{organization_id}/cases/{case_id}/status",
    response_model=CaseResponse,
)
def update_case_status(
    case_id: UUID,
    payload: CaseStatusUpdate,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> CaseResponse:
    _require_analyst(membership)
    case = session.scalar(
        select(IncidentCase)
        .where(
            IncidentCase.id == str(case_id),
            IncidentCase.organization_id == membership.organization_id,
        )
        .with_for_update()
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if payload.status != case.status and payload.status not in CASE_TRANSITIONS[case.status]:
        raise HTTPException(status_code=409, detail="Invalid case status transition")
    if payload.status != case.status:
        old_status = case.status
        now = datetime.now(UTC)
        case.status = payload.status
        case.updated_at = now
        case.closed_at = now if payload.status in {"resolved", "false_positive"} else None
        session.add(
            AuditEvent(
                organization_id=membership.organization_id,
                actor_user_id=membership.user_id,
                actor_type="user",
                action="case.status_changed",
                target_type="incident_case",
                target_id=case.id,
                details=json.dumps(
                    {"from": old_status, "to": payload.status}, separators=(",", ":")
                ),
            )
        )
        session.commit()
    scan = _case_scan(session, case)
    return _case_response(case, scan.hostname, _findings_for_case(session, case))
