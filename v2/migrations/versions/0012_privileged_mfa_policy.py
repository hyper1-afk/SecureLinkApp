"""Require MFA for privileged organization roles after a grace period.

Revision ID: 0012_privileged_mfa_policy
Revises: 0011_priority_case_notifications
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0012_privileged_mfa_policy"
down_revision: Union[str, None] = "0011_priority_case_notifications"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("privileged_mfa_grace_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        """
        UPDATE users
        SET privileged_mfa_grace_expires_at = CURRENT_TIMESTAMP + INTERVAL '7 days'
        WHERE mfa_enabled = false
          AND id IN (
              SELECT DISTINCT user_id FROM memberships WHERE role IN ('owner', 'admin')
          )
        """
    )


def downgrade() -> None:
    op.drop_column("users", "privileged_mfa_grace_expires_at")
