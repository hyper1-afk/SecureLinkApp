from __future__ import annotations

import logging
import smtplib
import time
from datetime import UTC, datetime, timedelta

from cryptography.fernet import InvalidToken
from sqlalchemy import or_, select

from apps.api import notification_worker
from apps.api.db import get_session_factory
from apps.api.emailer import decrypt_action_token, send_action_email
from packages.security_core.models import EmailActionToken, User

logger = logging.getLogger(__name__)
LEASE = timedelta(minutes=2)
MAX_ATTEMPTS = 8


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def process_one() -> bool:
    now = datetime.now(UTC)
    factory = get_session_factory()
    with factory() as session:  # noqa: SIM117
        with session.begin():
            row = session.scalar(
                select(EmailActionToken)
                .where(
                    or_(
                        (EmailActionToken.delivery_state == "pending")
                        & (EmailActionToken.next_delivery_at <= now),
                        (EmailActionToken.delivery_state == "sending")
                        & (EmailActionToken.delivery_lease_until < now),
                    )
                )
                .order_by(EmailActionToken.next_delivery_at, EmailActionToken.created_at)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if row is None:
                return False
            if row.consumed_at is not None or _as_utc(row.expires_at) <= now:
                row.delivery_state = "cancelled" if row.consumed_at is not None else "failed"
                row.delivery_ciphertext = None
                row.delivery_lease_until = None
                return True
            user = session.get(User, row.user_id)
            if user is None or not user.is_active or row.delivery_ciphertext is None:
                row.delivery_state = "failed"
                row.delivery_ciphertext = None
                row.delivery_lease_until = None
                row.last_delivery_error = "invalid_outbox_record"
                return True
            token_id = row.id
            purpose = row.purpose
            recipient = user.email
            ciphertext = row.delivery_ciphertext
            row.delivery_state = "sending"
            row.delivery_attempts += 1
            row.delivery_lease_until = now + LEASE
            row.last_delivery_error = None

    try:
        token = decrypt_action_token(ciphertext)
        send_action_email(purpose, recipient, token)
    except (InvalidToken, OSError, RuntimeError, UnicodeDecodeError, ValueError, smtplib.SMTPException) as exc:
        # Keep logs free of token, message, and recipient data.
        error_code = type(exc).__name__[:60] or "delivery_error"
        logger.warning("Account email delivery failed (%s)", error_code)
        with factory() as session, session.begin():
            row = session.get(EmailActionToken, token_id, with_for_update=True)
            if row is not None and row.delivery_state == "sending":
                now = datetime.now(UTC)
                if _as_utc(row.expires_at) <= now or row.delivery_attempts >= MAX_ATTEMPTS:
                    row.delivery_state = "failed"
                    row.delivery_ciphertext = None
                    row.delivery_lease_until = None
                else:
                    delay = min(30 * (2 ** (row.delivery_attempts - 1)), 3600)
                    row.delivery_state = "pending"
                    row.next_delivery_at = now + timedelta(seconds=delay)
                    row.delivery_lease_until = None
                row.last_delivery_error = error_code
        return True

    with factory() as session, session.begin():
        row = session.get(EmailActionToken, token_id, with_for_update=True)
        if row is not None and row.delivery_state == "sending":
            row.delivery_state = "sent"
            row.delivered_at = datetime.now(UTC)
            row.delivery_ciphertext = None
            row.delivery_lease_until = None
            row.last_delivery_error = None
    return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    while True:
        processed = process_one()
        processed |= notification_worker.process_one()
        if not processed:
            time.sleep(2)


if __name__ == "__main__":
    main()
