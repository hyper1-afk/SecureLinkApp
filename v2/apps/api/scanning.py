from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.auth import organization_membership
from apps.api.db import get_session
from apps.api.rate_limits import rate_limit
from packages.security_core.models import AuditEvent, Finding, Membership, ScanEvidence, UrlScan
from packages.security_core.url_analysis import (
    PARSER_VERSION,
    InvalidScanURL,
    analyze_url,
    evidence_hash,
)

router = APIRouter()
MAX_SCAN_BODY_BYTES = 9000


class FindingResponse(BaseModel):
    id: str
    detector_code: str
    severity: str
    title: str
    description: str
    evidence_id: str


class ScanResponse(BaseModel):
    id: str
    status: str
    display_url: str
    hostname: str
    scheme: str
    created_at: datetime
    findings: list[FindingResponse]


def _require_scan_role(membership: Membership) -> None:
    if membership.role not in {"owner", "admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst role or higher is required to scan URLs")


def _response(scan: UrlScan, findings: list[Finding]) -> ScanResponse:
    return ScanResponse(
        id=scan.id,
        status=scan.status,
        display_url=scan.display_url,
        hostname=scan.hostname,
        scheme=scan.scheme,
        created_at=scan.created_at,
        findings=[
            FindingResponse(
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


async def _read_scan_url(request: Request) -> str:
    content = bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content) > MAX_SCAN_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Scan request is too large")
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid scan request") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        raise HTTPException(status_code=422, detail="A URL string is required")
    return payload["url"]


@router.post(
    "/organizations/{organization_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("url_scan", 20, 60))],
)
async def create_url_scan(
    organization_id: str,
    request: Request,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> ScanResponse:
    _require_scan_role(membership)
    raw_url = await _read_scan_url(request)
    try:
        analysis = analyze_url(raw_url)
    except InvalidScanURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    observed_at = datetime.now(UTC)
    evidence_payload = {
        "observed_at": observed_at.isoformat(),
        "parser_version": PARSER_VERSION,
        "attributes": analysis.evidence,
    }
    serialized_evidence = json.dumps(evidence_payload, sort_keys=True, separators=(",", ":"))
    scan = UrlScan(
        organization_id=membership.organization_id,
        requested_by_user_id=membership.user_id,
        display_url=analysis.display_url,
        hostname=analysis.hostname,
        scheme=analysis.scheme,
        status="completed",
        created_at=observed_at,
    )
    session.add(scan)
    session.flush()
    evidence = ScanEvidence(
        organization_id=membership.organization_id,
        scan_id=scan.id,
        source_type="passive_url_parser",
        detector_version=PARSER_VERSION,
        content_hash=evidence_hash(evidence_payload),
        payload=serialized_evidence,
        created_at=observed_at,
    )
    session.add(evidence)
    session.flush()
    findings = [
        Finding(
            organization_id=membership.organization_id,
            scan_id=scan.id,
            evidence_id=evidence.id,
            detector_code=item.detector_code,
            severity=item.severity,
            title=item.title,
            description=item.description,
            created_at=observed_at,
        )
        for item in analysis.findings
    ]
    session.add_all(findings)
    session.add(
        AuditEvent(
            organization_id=membership.organization_id,
            actor_user_id=membership.user_id,
            actor_type="user",
            action="url_scan.completed",
            target_type="url_scan",
            target_id=scan.id,
            details=json.dumps(
                {"finding_count": len(findings), "parser_version": PARSER_VERSION},
                separators=(",", ":"),
            ),
        )
    )
    session.commit()
    return _response(scan, findings)


@router.get(
    "/organizations/{organization_id}/scans",
    response_model=list[ScanResponse],
)
def list_url_scans(
    organization_id: str,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[ScanResponse]:
    scans = session.scalars(
        select(UrlScan)
        .where(UrlScan.organization_id == membership.organization_id)
        .order_by(UrlScan.created_at.desc(), UrlScan.id)
        .limit(limit)
    ).all()
    if not scans:
        return []
    findings = session.scalars(
        select(Finding)
        .where(
            Finding.organization_id == membership.organization_id,
            Finding.scan_id.in_([scan.id for scan in scans]),
        )
        .order_by(Finding.created_at, Finding.detector_code)
    ).all()
    by_scan: dict[str, list[Finding]] = {scan.id: [] for scan in scans}
    for finding in findings:
        by_scan[finding.scan_id].append(finding)
    return [_response(scan, by_scan[scan.id]) for scan in scans]


@router.get(
    "/organizations/{organization_id}/scans/{scan_id}",
    response_model=ScanResponse,
)
def get_url_scan(
    organization_id: str,
    scan_id: UUID,
    membership: Annotated[Membership, Depends(organization_membership)],
    session: Annotated[Session, Depends(get_session)],
) -> ScanResponse:
    scan = session.scalar(
        select(UrlScan).where(
            UrlScan.id == str(scan_id),
            UrlScan.organization_id == membership.organization_id,
        )
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = session.scalars(
        select(Finding)
        .where(
            Finding.scan_id == scan.id,
            Finding.organization_id == membership.organization_id,
        )
        .order_by(Finding.created_at, Finding.detector_code)
    ).all()
    return _response(scan, findings)
