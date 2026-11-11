from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from apps.api.auth import organization_membership
from apps.api.db import get_session
from apps.api.rate_limits import rate_limit
from apps.api.spamhaus_drop import FEED_ID, FEED_SOURCE_URL, find_drop_match
from packages.security_core.models import (
    AuditEvent,
    CaseFinding,
    CaseSignal,
    Finding,
    IncidentCase,
    Membership,
    ScanEvidence,
    SecurityNotificationOutbox,
    SecuritySignal,
    ThreatFeedSnapshot,
    ThreatIndicator,
    UrlScan,
    User,
)
from packages.security_core.url_analysis import (
    PARSER_VERSION,
    FindingDraft,
    InvalidScanURL,
    analyze_url,
    evidence_hash,
)

router = APIRouter()
MAX_SCAN_BODY_BYTES = 9000


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class FindingResponse(BaseModel):
    id: str
    detector_code: str
    severity: str
    title: str
    description: str
    evidence_id: str


class ThreatIntelligenceResponse(BaseModel):
    source: str
    source_url: str
    status: str
    source_updated_at: datetime | None = None
    expires_at: datetime | None = None
    match: dict[str, str] | None = None
    reason: str | None = None


class ScanResponse(BaseModel):
    id: str
    status: str
    display_url: str
    hostname: str
    scheme: str
    created_at: datetime
    findings: list[FindingResponse]
    threat_intelligence: ThreatIntelligenceResponse | None = None


def _require_scan_role(membership: Membership) -> None:
    if membership.role not in {"owner", "admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst role or higher is required to scan URLs")


def _response(
    scan: UrlScan,
    findings: list[Finding],
    evidence: ScanEvidence | None = None,
) -> ScanResponse:
    threat_intelligence = None
    if evidence is not None:
        try:
            payload = json.loads(evidence.payload)
        except (TypeError, json.JSONDecodeError):
            payload = {}
        raw_intel = payload.get("threat_intelligence") if isinstance(payload, dict) else None
        if isinstance(raw_intel, dict):
            expires_at = raw_intel.get("expires_at")
            try:
                parsed_expiry = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else None
            except ValueError:
                parsed_expiry = None
            recorded_current = raw_intel.get("status") == "current"
            currently_fresh = (
                parsed_expiry is not None
                and _utc(parsed_expiry) > datetime.now(UTC)
            )
            response_status = (
                "current" if recorded_current and currently_fresh
                else "stale" if recorded_current
                else "unavailable"
            )
            raw_match = raw_intel.get("match")
            match = None
            if isinstance(raw_match, dict) and isinstance(raw_match.get("cidr"), str) and isinstance(raw_match.get("sblid"), str):
                match = {"cidr": raw_match["cidr"], "sblid": raw_match["sblid"]}
            threat_intelligence = ThreatIntelligenceResponse(
                source="Spamhaus Project DROP",
                source_url=FEED_SOURCE_URL,
                status=response_status,
                source_updated_at=raw_intel.get("source_updated_at"),
                expires_at=expires_at,
                match=match,
                reason=(
                    "No current feed snapshot is available."
                    if response_status == "unavailable"
                    else "The snapshot was current when scanned but has since expired."
                    if response_status == "stale"
                    else None
                ),
            )
    return ScanResponse(
        id=scan.id,
        status=scan.status,
        display_url=scan.display_url,
        hostname=scan.hostname,
        scheme=scan.scheme,
        created_at=scan.created_at,
        threat_intelligence=threat_intelligence,
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


async def _read_scan_payload(request: Request) -> tuple[str, dict[str, object]]:
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
    return payload["url"], payload


async def _read_scan_url(request: Request) -> str:
    raw_url, _payload = await _read_scan_payload(request)
    return raw_url


def _read_client_redactions(payload: dict[str, object]) -> dict[str, bool | int] | None:
    redactions = payload.get("redactions")
    if redactions is None:
        return None
    if not isinstance(redactions, dict):
        raise HTTPException(status_code=422, detail="Invalid URL privacy metadata")
    credentials_removed = redactions.get("credentials_removed")
    fragment_removed = redactions.get("fragment_removed")
    sensitive_count = redactions.get("sensitive_query_values_removed")
    if (
        type(credentials_removed) is not bool
        or type(fragment_removed) is not bool
        or type(sensitive_count) is not int
        or not 0 <= sensitive_count <= 64
        or set(redactions) != {
            "credentials_removed", "fragment_removed", "sensitive_query_values_removed"
        }
    ):
        raise HTTPException(status_code=422, detail="Invalid URL privacy metadata")
    return {
        "credentials_removed": credentials_removed,
        "fragment_removed": fragment_removed,
        "sensitive_query_values_removed": sensitive_count,
    }


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
    return await _create_scan(raw_url, membership.organization_id, membership.user_id, session, "url_scan")


async def _create_scan(
    raw_url: str,
    organization_id: str,
    user_id: str,
    session: Session,
    source_type: str = "url_scan",
    client_reported_redactions: dict[str, bool | int] | None = None,
) -> ScanResponse:
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
    feed_snapshot = session.get(ThreatFeedSnapshot, FEED_ID)
    feed_expires_at = _utc(feed_snapshot.expires_at) if feed_snapshot else None
    feed_available = feed_snapshot is not None and feed_expires_at > observed_at
    if feed_available:
        evidence_payload["threat_intelligence"] = {
            "source": "Spamhaus Project DROP",
            "source_url": FEED_SOURCE_URL,
            "source_updated_at": _utc(feed_snapshot.source_updated_at).isoformat(),
            "expires_at": feed_expires_at.isoformat(),
            "entry_count": feed_snapshot.entry_count,
            "content_hash": feed_snapshot.content_hash,
            "status": "current",
        }
        try:
            address = ipaddress.ip_address(analysis.hostname)
        except ValueError:
            address = None
        if address is not None and address.is_global:
            match = find_drop_match(
                str(address), feed_snapshot.payload, feed_expires_at, observed_at,
            )
            if match:
                evidence_payload["threat_intelligence"]["match"] = match
    else:
        evidence_payload["threat_intelligence"] = {
            "source": "Spamhaus Project DROP",
            "source_url": FEED_SOURCE_URL,
            "status": "unavailable",
            "reason": "No current feed snapshot is available.",
        }
    if source_type == "extension_scan" and client_reported_redactions is not None:
        evidence_payload["client_reported_redactions"] = client_reported_redactions
    serialized_evidence = json.dumps(evidence_payload, sort_keys=True, separators=(",", ":"))
    scan = UrlScan(
        organization_id=organization_id,
        requested_by_user_id=user_id,
        display_url=analysis.display_url,
        hostname=analysis.hostname,
        scheme=analysis.scheme,
        status="completed",
        created_at=observed_at,
    )
    session.add(scan)
    session.flush()
    evidence = ScanEvidence(
        organization_id=organization_id,
        scan_id=scan.id,
        source_type="passive_url_parser",
        detector_version=PARSER_VERSION,
        content_hash=evidence_hash(evidence_payload),
        payload=serialized_evidence,
        created_at=observed_at,
    )
    session.add(evidence)
    session.flush()
    finding_drafts = list(analysis.findings)
    threat_intelligence = evidence_payload["threat_intelligence"]
    if isinstance(threat_intelligence, dict) and isinstance(threat_intelligence.get("match"), dict):
        match = threat_intelligence["match"]
        finding_drafts.append(FindingDraft(
            "spamhaus_drop_network_match",
            "high",
            "IP address is listed in Spamhaus DROP",
            (
                f"The public IP belongs to {match['cidr']} ({match['sblid']}) in the Spamhaus Project "
                f"DROP dataset, dated {_utc(feed_snapshot.source_updated_at).date().isoformat()}. "
                f"This is a high-priority indicator for review, not proof about page content. "
                f"Source: {FEED_SOURCE_URL}"
            ),
        ))
    if session.scalar(select(ThreatIndicator.id).where(
        ThreatIndicator.organization_id == organization_id,
        ThreatIndicator.hostname == analysis.hostname,
    )):
        finding_drafts.append(FindingDraft(
            "tenant_threat_indicator_match", "medium", "Hostname matches an organization indicator",
            "This hostname exactly matches an indicator maintained by your organization. Review its source and context; this match alone is not a safety verdict.",
        ))
    findings = [
        Finding(
            organization_id=organization_id,
            scan_id=scan.id,
            evidence_id=evidence.id,
            detector_code=item.detector_code,
            severity=item.severity,
            title=item.title,
            description=item.description,
            created_at=observed_at,
        )
        for item in finding_drafts
    ]
    session.add_all(findings)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    signal_severity = min(
        (finding.severity for finding in findings),
        key=severity_rank.__getitem__,
        default="informational",
    )
    signal = SecuritySignal(
        organization_id=organization_id,
        source_type=source_type,
        source_reference=scan.id,
        signal_type="passive_url_hygiene",
        subject=scan.hostname,
        severity=signal_severity,
        title="URL hygiene scan observed",
        summary=(
            f"Passive URL analysis completed with {len(findings)} indicator(s); "
            "available reputation data is time-bounded, and results are not a safety verdict."
        ),
        observed_at=observed_at,
        payload=serialized_evidence,
        content_hash=evidence_hash(evidence_payload),
        created_at=observed_at,
    )
    session.add(signal)
    session.flush()
    priority_findings = [item for item in findings if item.severity in {"critical", "high"}]
    if priority_findings:
        if session.bind is not None and session.bind.dialect.name == "postgresql":
            lock_key = int.from_bytes(
                hashlib.sha256(f"{organization_id}:{scan.hostname}".encode()).digest()[:8],
                byteorder="big",
                signed=True,
            )
            session.execute(select(func.pg_advisory_xact_lock(lock_key)))
        case = session.scalar(
            select(IncidentCase)
            .join(UrlScan, IncidentCase.scan_id == UrlScan.id)
            .where(
                IncidentCase.organization_id == organization_id,
                IncidentCase.status.in_(("open", "investigating", "awaiting_approval")),
                IncidentCase.title == f"Review high-priority URL signals for {scan.hostname}",
                UrlScan.hostname == scan.hostname,
            )
            .order_by(IncidentCase.updated_at.desc(), IncidentCase.id)
            .limit(1)
            .with_for_update()
        )
        created_case = case is None
        priority_severity = min(
            (item.severity for item in priority_findings), key=severity_rank.__getitem__
        )
        if created_case:
            case = IncidentCase(
                organization_id=organization_id,
                scan_id=scan.id,
                created_by_user_id=None,
                status="open",
                severity=priority_severity,
                title=f"Review high-priority URL signals for {scan.hostname}",
                summary=(
                    f"Automatic triage opened this case after detecting {len(priority_findings)} "
                    "high-priority URL indicator(s). Review the evidence; this is not a safety verdict."
                ),
                created_at=observed_at,
                updated_at=observed_at,
            )
            session.add(case)
            session.flush()
        else:
            case.severity = min((case.severity, priority_severity), key=severity_rank.__getitem__)
            case.updated_at = observed_at
        session.add(CaseSignal(
            organization_id=organization_id, case_id=case.id, signal_id=signal.id,
        ))
        if created_case:
            recipients = session.execute(
                select(Membership.user_id).join(User, User.id == Membership.user_id).where(
                    Membership.organization_id == organization_id,
                    Membership.role.in_(("owner", "admin")),
                    Membership.priority_email_enabled.is_(True),
                    User.is_active.is_(True),
                    User.email_verified.is_(True),
                )
            ).scalars().all()
            session.add_all(
                SecurityNotificationOutbox(organization_id=organization_id, case_id=case.id, user_id=recipient)
                for recipient in recipients
            )
        session.add_all(
            CaseFinding(
                organization_id=organization_id,
                case_id=case.id,
                finding_id=finding.id,
            )
            for finding in findings
        )
        session.add(
            AuditEvent(
                organization_id=organization_id,
                actor_user_id=None,
                actor_type="system",
                action="case.auto_created_from_scan" if created_case else "case.auto_updated_from_scan",
                target_type="incident_case",
                target_id=case.id,
                details=json.dumps(
                    {
                        "scan_id": scan.id,
                        "finding_count": len(findings),
                        "priority_finding_count": len(priority_findings),
                        "triggering_severity": priority_severity,
                        "triage_version": "url-priority-v2",
                    },
                    separators=(",", ":"),
                ),
            )
        )
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=user_id,
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
    return _response(scan, findings, evidence)


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
    evidence_rows = session.scalars(
        select(ScanEvidence).where(
            ScanEvidence.organization_id == membership.organization_id,
            ScanEvidence.scan_id.in_([scan.id for scan in scans]),
            ScanEvidence.source_type == "passive_url_parser",
        )
    ).all()
    by_scan: dict[str, list[Finding]] = {scan.id: [] for scan in scans}
    evidence_by_scan = {item.scan_id: item for item in evidence_rows}
    for finding in findings:
        by_scan[finding.scan_id].append(finding)
    return [_response(scan, by_scan[scan.id], evidence_by_scan.get(scan.id)) for scan in scans]


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
    evidence = session.scalar(
        select(ScanEvidence).where(
            ScanEvidence.scan_id == scan.id,
            ScanEvidence.organization_id == membership.organization_id,
            ScanEvidence.source_type == "passive_url_parser",
        )
    )
    return _response(scan, findings, evidence)

