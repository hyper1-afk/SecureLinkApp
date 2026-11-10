"""Add opt-out priority email notifications and durable delivery state.

Revision ID: 0011_priority_case_notifications
Revises: 0010_account_mfa
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0011_priority_case_notifications"
down_revision: Union[str, None] = "0010_account_mfa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "memberships",
        sa.Column("priority_email_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.create_table(
        "security_notification_outbox",
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("delivery_state", sa.String(12), server_default="pending", nullable=False),
        sa.Column("delivery_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_delivery_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("delivery_lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivery_error", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_security_notification_case_organization",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("case_id", "user_id", name="uq_security_notification_case_user"),
        sa.CheckConstraint(
            "delivery_state IN ('pending', 'sending', 'sent', 'failed', 'cancelled')",
            name="ck_security_notification_delivery_state",
        ),
    )
    op.create_index(
        "ix_security_notification_delivery",
        "security_notification_outbox",
        ["delivery_state", "next_delivery_at"],
    )
    op.create_index(
        "ix_security_notification_org_state_created",
        "security_notification_outbox",
        ["organization_id", "delivery_state", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_security_notification_org_state_created", table_name="security_notification_outbox")
    op.drop_index("ix_security_notification_delivery", table_name="security_notification_outbox")
    op.drop_table("security_notification_outbox")
    op.drop_column("memberships", "priority_email_enabled")
