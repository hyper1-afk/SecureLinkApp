from __future__ import annotations

import logging
import smtplib
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select

from apps.api.db import get_session_factory
from apps.api.emailer import send_high_priority_case_email
from packages.security_core.models import (
    IncidentCase,
    Membership,
    Organization,
    SecurityNotificationOutbox,
    UrlScan,
    User,
)

logger = logging.getLogger(__name__)
LEASE = timedelta(minutes=2)
MAX_ATTEMPTS = 8


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def process_one() -> bool:
    now = datetime.now(UTC)
    factory = get_session_factory()
    with factory() as session, session.begin():
        row = session.scalar(
                select(SecurityNotificationOutbox).where(
                    or_(
                        (SecurityNotificationOutbox.delivery_state == "pending")
                        & (SecurityNotificationOutbox.next_delivery_at <= now),
                        (SecurityNotificationOutbox.delivery_state == "sending")
                        & (SecurityNotificationOutbox.delivery_lease_until < now),
                    )
                ).order_by(SecurityNotificationOutbox.next_delivery_at,
                           SecurityNotificationOutbox.created_at).with_for_update(skip_locked=True).limit(1)
        )
        if row is None:
            return False
        if row.delivery_attempts >= MAX_ATTEMPTS:
            row.delivery_state = "failed"
            row.delivery_lease_until = None
            row.last_delivery_error = "attempt_limit_reached"
            return True
        member = session.scalar(select(Membership).where(
                Membership.organization_id == row.organization_id,
                Membership.user_id == row.user_id,
            ))
        user = session.get(User, row.user_id)
        case = session.get(IncidentCase, row.case_id)
        organization = session.get(Organization, row.organization_id)
        scan = session.get(UrlScan, case.scan_id) if case is not None else None
        if (member is None or member.role not in {"owner", "admin"}
                or not member.priority_email_enabled or user is None
                or not user.is_active or not user.email_verified
                or case is None or case.severity not in {"critical", "high"}
                or organization is None or scan is None):
            row.delivery_state = "cancelled"
            row.delivery_lease_until = None
            return True
        delivery = (row.id, user.email, organization.name, case.severity, scan.hostname, case.id)
        row.delivery_state = "sending"
        row.delivery_attempts += 1
        row.delivery_lease_until = now + LEASE
        row.last_delivery_error = None

    notification_id, recipient, organization_name, severity, hostname, case_id = delivery
    try:
        send_high_priority_case_email(recipient, organization_name, severity, hostname, case_id)
    except (OSError, RuntimeError, ValueError, UnicodeError, smtplib.SMTPException) as exc:
        error_code = type(exc).__name__[:60] or "delivery_error"
        logger.warning("Priority case email delivery failed (%s)", error_code)
        with factory() as session, session.begin():
            row = session.get(SecurityNotificationOutbox, notification_id, with_for_update=True)
            if row is not None and row.delivery_state == "sending":
                now = datetime.now(UTC)
                if row.delivery_attempts >= MAX_ATTEMPTS:
                    row.delivery_state = "failed"
                    row.delivery_lease_until = None
                else:
                    delay = min(30 * (2 ** (row.delivery_attempts - 1)), 3600)
                    row.delivery_state = "pending"
                    row.next_delivery_at = now + timedelta(seconds=delay)
                    row.delivery_lease_until = None
                row.last_delivery_error = error_code
        return True

    with factory() as session, session.begin():
        row = session.get(SecurityNotificationOutbox, notification_id, with_for_update=True)
        if row is not None and row.delivery_state == "sending":
            row.delivery_state = "sent"
            row.delivered_at = datetime.now(UTC)
            row.delivery_lease_until = None
            row.last_delivery_error = None
    return True
