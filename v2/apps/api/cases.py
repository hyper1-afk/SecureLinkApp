from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.auth import organization_membership
from apps.api.db import get_session
from apps.api.rate_limits import rate_limit
from packages.security_core.models import (
    AuditEvent,
    CaseFinding,
    CaseNote,
    CaseSignal,
    Finding,
    IncidentCase,
    Membership,
    SecuritySignal,
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


class CaseNoteCreate(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


class CaseNoteResponse(BaseModel):
    id: str
    created_by_user_id: str | None
    content: str
    created_at: datetime


class CaseFindingResponse(BaseModel):
    id: str
    detector_code: str
    severity: str
    title: str
    description: str
    evidence_id: str


class SignalResponse(BaseModel):
    id: str
    source_type: str
    signal_type: str
    subject: str
    severity: str
    title: str
    summary: str
    observed_at: datetime


class CaseResponse(BaseModel):
    id: str
    scan_id: str | None
    status: str
    severity: str
    title: str
    summary: str
    hostname: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    findings: list[CaseFindingResponse]
    signals: list[SignalResponse]
    notes: list[CaseNoteResponse]


def _require_analyst(membership: Membership) -> None:
    if membership.role not in {"owner", "admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst role or higher is required")


def _case_response(
    case: IncidentCase,
    hostname: str,
    findings: list[Finding],
    signals: list[SecuritySignal],
    notes: list[CaseNote],
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
        signals=[
            SignalResponse(
                id=signal.id,
                source_type=signal.source_type,
                signal_type=signal.signal_type,
                subject=signal.subject,
                severity=signal.severity,
                title=signal.title,
                summary=signal.summary,
                observed_at=signal.observed_at,
            )
            for signal in signals
        ],
        notes=[
            CaseNoteResponse(
                id=note.id,
                created_by_user_id=note.created_by_user_id,
                content=note.content,
                created_at=note.created_at,
            )
            for note in notes
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


def _case_signals(session: Session, case: IncidentCase) -> list[SecuritySignal]:
    return session.scalars(
        select(SecuritySignal)
        .join(CaseSignal, CaseSignal.signal_id == SecuritySignal.id)
        .where(
            CaseSignal.case_id == case.id,
            CaseSignal.organization_id == case.organization_id,
            SecuritySignal.organization_id == case.organization_id,
        )
        .order_by(SecuritySignal.observed_at, SecuritySignal.id)
    ).all()


def _case_notes(session: Session, case: IncidentCase) -> list[CaseNote]:
    return session.scalars(
        select(CaseNote)
        .where(CaseNote.case_id == case.id, CaseNote.organization_id == case.organization_id)
        .order_by(CaseNote.created_at.desc(), CaseNote.id)
        .limit(25)
    ).all()


def _case_scan(session: Session, case: IncidentCase) -> UrlScan | None:
    if case.scan_id is None:
        return None
    scan = session.scalar(
        select(UrlScan).where(
            UrlScan.id == case.scan_id,
            UrlScan.organization_id == case.organization_id,
        )
    )
    if scan is None and case.scan_id is not None:
        raise HTTPException(status_code=404, detail="Case not found")
    return scan


def _case_response_for_session(session: Session, case: IncidentCase) -> CaseResponse:
    scan = _case_scan(session, case)
    signals = _case_signals(session, case)
    subject = scan.hostname if scan is not None else signals[0].subject if signals else None
    if subject is None:
        raise HTTPException(status_code=404, detail="Case evidence not found")
    return _case_response(
        case, subject, _findings_for_case(session, case), signals, _case_notes(session, case)
    )


@router.get("/organizations/{organization_id}/signals", response_model=list[SignalResponse])
def list_security_signals(
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[SignalResponse]:
    signals = session.scalars(
        select(SecuritySignal)
        .where(SecuritySignal.organization_id == membership.organization_id)
        .order_by(SecuritySignal.observed_at.desc(), SecuritySignal.id)
        .limit(limit)
    ).all()
    return [
        SignalResponse(
            id=signal.id,
            source_type=signal.source_type,
            signal_type=signal.signal_type,
            subject=signal.subject,
            severity=signal.severity,
            title=signal.title,
            summary=signal.summary,
            observed_at=signal.observed_at,
        )
        for signal in signals
    ]


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
        return _case_response_for_session(session, existing)

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
    signal = session.scalar(
        select(SecuritySignal).where(
            SecuritySignal.organization_id == membership.organization_id,
            SecuritySignal.source_reference == scan.id,
            SecuritySignal.source_type.in_(("url_scan", "extension_scan")),
        )
    )
    if signal is None:
        raise HTTPException(status_code=404, detail="Scan signal not found")
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
    session.add(CaseSignal(
        organization_id=membership.organization_id, case_id=case.id, signal_id=signal.id,
    ))
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
        return _case_response_for_session(session, existing)
    return _case_response_for_session(session, case)


@router.post(
    "/organizations/{organization_id}/cases/from-signal/{signal_id}",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_case_from_signal(
    signal_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
    response: Response,
) -> CaseResponse:
    _require_analyst(membership)
    signal = session.scalar(select(SecuritySignal).where(
        SecuritySignal.id == str(signal_id),
        SecuritySignal.organization_id == membership.organization_id,
    ))
    if signal is None:
        raise HTTPException(status_code=404, detail="Signal not found")
    existing = session.scalar(
        select(IncidentCase)
        .join(CaseSignal, CaseSignal.case_id == IncidentCase.id)
        .where(
            CaseSignal.signal_id == signal.id,
            CaseSignal.organization_id == membership.organization_id,
            IncidentCase.organization_id == membership.organization_id,
        )
    )
    if existing is not None:
        response.status_code = status.HTTP_200_OK
        return _case_response_for_session(session, existing)

    scan = None
    if signal.source_type in {"url_scan", "extension_scan"}:
        scan = session.scalar(select(UrlScan).where(
            UrlScan.id == signal.source_reference,
            UrlScan.organization_id == membership.organization_id,
        ))
        if scan is None:
            raise HTTPException(status_code=404, detail="Signal source not found")
        findings = session.scalars(select(Finding).where(
            Finding.scan_id == scan.id,
            Finding.organization_id == membership.organization_id,
        )).all()
        if not findings:
            raise HTTPException(status_code=409, detail="This signal has no findings to open as a case")
    else:
        findings = []

    now = datetime.now(UTC)
    case = IncidentCase(
        organization_id=membership.organization_id,
        scan_id=scan.id if scan is not None else None,
        created_by_user_id=membership.user_id,
        status="open",
        severity=signal.severity,
        title=f"Review {signal.title[:160]}",
        summary=(signal.summary[:400] + " Review the original evidence before taking action."),
        created_at=now,
        updated_at=now,
    )
    session.add(case)
    session.flush()
    session.add(CaseSignal(
        organization_id=membership.organization_id, case_id=case.id, signal_id=signal.id,
    ))
    session.add_all(
        CaseFinding(organization_id=membership.organization_id, case_id=case.id, finding_id=finding.id)
        for finding in findings
    )
    session.add(AuditEvent(
        organization_id=membership.organization_id,
        actor_user_id=membership.user_id,
        actor_type="user",
        action="case.created_from_signal",
        target_type="incident_case",
        target_id=case.id,
        details=json.dumps({"signal_id": signal.id, "source_type": signal.source_type}, separators=(",", ":")),
    ))
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        existing = session.scalar(
            select(IncidentCase)
            .join(CaseSignal, CaseSignal.case_id == IncidentCase.id)
            .where(
                CaseSignal.signal_id == signal.id,
                CaseSignal.organization_id == membership.organization_id,
                IncidentCase.organization_id == membership.organization_id,
            )
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="Signal is already linked to a case") from exc
        response.status_code = status.HTTP_200_OK
        return _case_response_for_session(session, existing)
    return _case_response_for_session(session, case)


@router.post(
    "/organizations/{organization_id}/cases/{case_id}/signals/{signal_id}",
    response_model=CaseResponse,
)
def attach_signal_to_case(
    case_id: UUID,
    signal_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
    response: Response,
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
    signal = session.scalar(
        select(SecuritySignal)
        .where(
            SecuritySignal.id == str(signal_id),
            SecuritySignal.organization_id == membership.organization_id,
        )
        .with_for_update()
    )
    if case is None or signal is None:
        raise HTTPException(status_code=404, detail="Case or signal not found")

    existing_link = session.scalar(
        select(CaseSignal).where(
            CaseSignal.signal_id == signal.id,
            CaseSignal.organization_id == membership.organization_id,
        )
    )
    if existing_link is not None:
        if existing_link.case_id != case.id:
            raise HTTPException(status_code=409, detail="Signal is already linked to another case")
        response.status_code = status.HTTP_200_OK
        return _case_response_for_session(session, case)
    if case.status in {"resolved", "false_positive"}:
        raise HTTPException(status_code=409, detail="Reopen the case before linking another signal")

    session.add(CaseSignal(
        organization_id=membership.organization_id,
        case_id=case.id,
        signal_id=signal.id,
    ))
    if SEVERITY_RANK[signal.severity] < SEVERITY_RANK[case.severity]:
        case.severity = signal.severity
    case.updated_at = datetime.now(UTC)
    session.add(AuditEvent(
        organization_id=membership.organization_id,
        actor_user_id=membership.user_id,
        actor_type="user",
        action="case.signal_linked",
        target_type="incident_case",
        target_id=case.id,
        details=json.dumps({"signal_id": signal.id}, separators=(",", ":")),
    ))
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(status_code=409, detail="Signal was linked to another case concurrently") from exc
    return _case_response_for_session(session, case)


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
        result.append(_case_response_for_session(session, case))
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
    return _case_response_for_session(session, case)


@router.post(
    "/organizations/{organization_id}/cases/{case_id}/notes",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("case_note", 30, 60))],
)
def add_case_note(
    case_id: UUID,
    payload: CaseNoteCreate,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> CaseResponse:
    _require_analyst(membership)
    case = session.scalar(
        select(IncidentCase).where(
            IncidentCase.id == str(case_id),
            IncidentCase.organization_id == membership.organization_id,
        )
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=422, detail="Note cannot be blank")
    note = CaseNote(
        organization_id=membership.organization_id,
        case_id=case.id,
        created_by_user_id=membership.user_id,
        content=content,
    )
    case.updated_at = datetime.now(UTC)
    session.add(note)
    session.flush()
    session.add(AuditEvent(
        organization_id=membership.organization_id,
        actor_user_id=membership.user_id,
        actor_type="user",
        action="case.note_added",
        target_type="incident_case",
        target_id=case.id,
        details=json.dumps({"note_id": note.id}, separators=(",", ":")),
    ))
    session.commit()
    return _case_response_for_session(session, case)


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
    return _case_response_for_session(session, case)
