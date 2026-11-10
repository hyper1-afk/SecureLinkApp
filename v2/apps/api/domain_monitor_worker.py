from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta

import dns.exception
import dns.resolver
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db import get_session_factory
from packages.security_core.models import (
    AuditEvent,
    CaseSignal,
    DomainAsset,
    DomainMonitorState,
    IncidentCase,
    Membership,
    SecurityNotificationOutbox,
    SecuritySignal,
    User,
)

logger = logging.getLogger(__name__)
MONITOR_TYPE = "email_dns_security"
CHECK_INTERVAL = timedelta(hours=6)
RETRY_INTERVAL = timedelta(minutes=15)
LEASE = timedelta(minutes=2)
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _query_txt(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    try:
        answers = resolver.resolve(name, "TXT")
    except dns.resolver.NoAnswer:
        return []
    except (dns.exception.DNSException, OSError):
        raise
    return [b"".join(answer.strings).decode("utf-8", "replace").strip() for answer in answers]


def collect_issues(hostname: str, resolver: dns.resolver.Resolver) -> dict[str, dict[str, str]]:
    """Check public SPF/DMARC TXT records only; never connect to resolved addresses."""
    try:
        root_records = _query_txt(resolver, hostname)
    except dns.resolver.NXDOMAIN:
        return {
            "domain_nxdomain": {
                "severity": "high",
                "title": "Verified domain no longer resolves",
                "summary": "The verified domain returned NXDOMAIN during a DNS-only check. Confirm registration and authoritative DNS.",
            }
        }

    spf_records = [
        record
        for record in root_records
        if (parts := record.casefold().split(None, 1)) and parts[0] == "v=spf1"
    ]
    if not spf_records:
        spf: dict[str, str] = {
            "severity": "medium",
            "title": "SPF record not found",
            "summary": "No SPF TXT record was observed at the verified domain. If this domain sends email, configure and verify an SPF policy.",
        }
    elif len(spf_records) > 1:
        spf = {
            "severity": "high",
            "title": "Multiple SPF records found",
            "summary": "More than one SPF TXT record was observed. Mail receivers may treat multiple SPF policies as a permanent error.",
        }
    else:
        spf = {}

    try:
        dmarc_records = _query_txt(resolver, f"_dmarc.{hostname}")
    except dns.resolver.NXDOMAIN:
        dmarc_records = []
    dmarc_records = [
        record
        for record in dmarc_records
        if record.casefold().split(";", 1)[0].strip() == "v=dmarc1"
    ]
    if not dmarc_records:
        dmarc: dict[str, str] = {
            "severity": "medium",
            "title": "DMARC record not found",
            "summary": "No DMARC TXT record was observed. If this domain sends email, publish a DMARC policy and validate its reporting destination.",
        }
    elif len(dmarc_records) > 1:
        dmarc = {
            "severity": "high",
            "title": "Multiple DMARC records found",
            "summary": "More than one DMARC TXT record was observed. Receivers may reject or inconsistently interpret the policy.",
        }
    else:
        tags = {}
        for part in dmarc_records[0].split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip().casefold()] = value.strip().casefold()
        if tags.get("p") == "none":
            dmarc = {
                "severity": "low",
                "title": "DMARC policy is monitor-only",
                "summary": "The DMARC policy is p=none. This collects policy reports but does not ask receivers to quarantine or reject failing mail.",
            }
        elif tags.get("p") not in {"quarantine", "reject"}:
            dmarc = {
                "severity": "medium",
                "title": "DMARC policy is incomplete",
                "summary": "A DMARC record was found but did not contain a recognized p=none, p=quarantine, or p=reject policy.",
            }
        else:
            dmarc = {}

    issues = {}
    if spf:
        issues["spf_policy"] = spf
    if dmarc:
        issues["dmarc_policy"] = dmarc
    return issues


def _make_resolver() -> dns.resolver.Resolver:
    settings = get_settings()
    if settings.app_env in {"staging", "production"}:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [
            item.strip() for item in settings.domain_dns_resolvers.split(",") if item.strip()
        ]
    else:
        resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 5
    return resolver


def _claim_one(now: datetime) -> tuple[str, str, str] | None:
    factory = get_session_factory()
    with factory() as session, session.begin():
        state = session.scalar(
            select(DomainMonitorState)
            .join(
                DomainAsset,
                and_(
                    DomainAsset.id == DomainMonitorState.asset_id,
                    DomainAsset.organization_id == DomainMonitorState.organization_id,
                ),
            )
            .where(
                DomainMonitorState.monitor_type == MONITOR_TYPE,
                DomainMonitorState.next_check_at <= now,
                or_(DomainMonitorState.lease_until.is_(None), DomainMonitorState.lease_until < now),
                DomainAsset.status == "verified",
                DomainAsset.monitoring_enabled.is_(True),
            )
            .order_by(DomainMonitorState.next_check_at, DomainMonitorState.asset_id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if state is None:
            return None
        asset = session.get(DomainAsset, state.asset_id)
        if asset is None:
            return None
        state.lease_until = now + LEASE
        state.last_error = None
        return (asset.id, asset.organization_id, asset.hostname)


def _release_after_error(asset_id: str, organization_id: str, exc: Exception) -> None:
    factory = get_session_factory()
    with factory() as session, session.begin():
        state = session.get(DomainMonitorState, (asset_id, organization_id, MONITOR_TYPE), with_for_update=True)
        if state is not None:
            state.lease_until = None
            state.next_check_at = datetime.now(UTC) + RETRY_INTERVAL
            state.last_error = type(exc).__name__[:64]
    logger.warning("Domain DNS monitor failed (%s)", type(exc).__name__[:60])


def _add_signal(
    session: Session,
    asset: DomainAsset,
    generation: int,
    signal_type: str,
    severity: str,
    title: str,
    summary: str,
    observed_at: datetime,
) -> SecuritySignal:
    payload = {
        "monitor_type": MONITOR_TYPE,
        "signal_type": signal_type,
        "observed_at": observed_at.isoformat(),
        "records_only": True,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signal = SecuritySignal(
        organization_id=asset.organization_id,
        source_type="domain_monitor",
        source_reference=f"{asset.id}:{generation}:{signal_type}",
        signal_type=signal_type,
        subject=asset.hostname,
        severity=severity,
        title=title,
        summary=summary,
        observed_at=observed_at,
        payload=serialized,
        content_hash=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        created_at=observed_at,
    )
    session.add(signal)
    session.flush()
    if severity in {"high", "critical"}:
        case = session.scalar(
            select(IncidentCase)
            .join(CaseSignal, CaseSignal.case_id == IncidentCase.id)
            .join(SecuritySignal, SecuritySignal.id == CaseSignal.signal_id)
            .where(
                IncidentCase.organization_id == asset.organization_id,
                IncidentCase.status.in_(("open", "investigating", "awaiting_approval")),
                CaseSignal.organization_id == asset.organization_id,
                SecuritySignal.organization_id == asset.organization_id,
                SecuritySignal.source_type == "domain_monitor",
                SecuritySignal.subject == asset.hostname,
            )
            .order_by(IncidentCase.updated_at.desc(), IncidentCase.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if case is not None:
            session.add(CaseSignal(
                organization_id=asset.organization_id,
                case_id=case.id,
                signal_id=signal.id,
            ))
            if SEVERITY_RANK[severity] < SEVERITY_RANK[case.severity]:
                case.severity = severity
            case.updated_at = observed_at
            session.add(AuditEvent(
                organization_id=asset.organization_id,
                actor_user_id=None,
                actor_type="system",
                action="case.signal_correlated_from_domain_monitor",
                target_type="incident_case",
                target_id=case.id,
                details=json.dumps({"signal_id": signal.id, "monitor_type": MONITOR_TYPE}, separators=(",", ":")),
            ))
            return signal

        case = IncidentCase(
            organization_id=asset.organization_id,
            scan_id=None,
            created_by_user_id=None,
            status="open",
            severity=severity,
            title=f"Review {title}"[:200],
            summary=f"{summary} Review the DNS evidence before taking action."[:512],
            created_at=observed_at,
            updated_at=observed_at,
        )
        session.add(case)
        session.flush()
        session.add(CaseSignal(
            organization_id=asset.organization_id,
            case_id=case.id,
            signal_id=signal.id,
        ))
        session.add(AuditEvent(
            organization_id=asset.organization_id,
            actor_user_id=None,
            actor_type="system",
            action="case.auto_created_from_domain_monitor",
            target_type="incident_case",
            target_id=case.id,
            details=json.dumps({"signal_id": signal.id, "monitor_type": MONITOR_TYPE}, separators=(",", ":")),
        ))
        recipients = session.execute(
            select(Membership.user_id)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == asset.organization_id,
                Membership.role.in_(("owner", "admin")),
                Membership.priority_email_enabled.is_(True),
                User.is_active.is_(True),
                User.email_verified.is_(True),
            )
        ).scalars().all()
        session.add_all(
            SecurityNotificationOutbox(
                organization_id=asset.organization_id,
                case_id=case.id,
                user_id=user_id,
            )
            for user_id in recipients
        )
    return signal


def _record_result(asset_id: str, organization_id: str, issues: dict[str, dict[str, str]]) -> None:
    now = datetime.now(UTC)
    factory = get_session_factory()
    with factory() as session, session.begin():
        state = session.get(DomainMonitorState, (asset_id, organization_id, MONITOR_TYPE), with_for_update=True)
        asset = session.scalar(select(DomainAsset).where(
            DomainAsset.id == asset_id,
            DomainAsset.organization_id == organization_id,
        ))
        if state is None:
            return
        if asset is None or asset.status != "verified" or not asset.monitoring_enabled:
            state.lease_until = None
            state.next_check_at = now + CHECK_INTERVAL
            return

        current = {code: issue["severity"] for code, issue in issues.items()}
        first_check = state.last_checked_at is None
        try:
            previous = json.loads(state.current_state)
            if not isinstance(previous, dict):
                previous = {}
        except (TypeError, ValueError):
            previous = {}
        changed = current != previous
        generation = state.generation + 1 if changed and (not first_check or current) else state.generation
        if changed and generation:
            resolved = set(previous) - set(current)
            for code, issue in issues.items():
                if previous.get(code) != issue["severity"]:
                    _add_signal(
                        session, asset, generation, code, issue["severity"], issue["title"],
                        issue["summary"], now,
                    )
            for code in sorted(resolved):
                _add_signal(
                    session,
                    asset,
                    generation,
                    f"{code}_resolved",
                    "informational",
                    "Domain DNS finding no longer observed",
                    f"The previous {code.replace('_', ' ')} condition was not observed in the latest DNS check. Confirm the current configuration independently.",
                    now,
                )
            session.add(AuditEvent(
                organization_id=organization_id,
                actor_user_id=None,
                actor_type="system",
                action="domain_monitor.state_changed",
                target_type="domain_asset",
                target_id=asset_id,
                details=json.dumps({
                    "monitor_type": MONITOR_TYPE,
                    "generation": generation,
                    "active_finding_codes": sorted(current),
                }, separators=(",", ":")),
            ))
        state.current_state = json.dumps(current, sort_keys=True, separators=(",", ":"))
        state.generation = generation
        state.last_checked_at = now
        state.next_check_at = now + CHECK_INTERVAL
        state.lease_until = None
        state.last_error = None


def process_one() -> bool:
    claim = _claim_one(datetime.now(UTC))
    if claim is None:
        return False
    asset_id, organization_id, hostname = claim
    resolver = _make_resolver()
    try:
        issues = collect_issues(hostname, resolver)
    except (dns.exception.DNSException, OSError) as exc:
        _release_after_error(asset_id, organization_id, exc)
        return True
    _record_result(asset_id, organization_id, issues)
    return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    while True:
        if not process_one():
            time.sleep(10)


if __name__ == "__main__":
    main()
