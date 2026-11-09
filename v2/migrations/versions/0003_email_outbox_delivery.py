"""Add encrypted durable delivery state for account-action email.

Revision ID: 0003_email_outbox_delivery
Revises: 0002_email_account_lifecycle
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_email_outbox_delivery"
down_revision: Union[str, None] = "0002_email_account_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("email_action_tokens", sa.Column("delivery_ciphertext", sa.LargeBinary(), nullable=True))
    # Existing tokens predate delivery state and must never be queued for email.
    op.add_column(
        "email_action_tokens",
        sa.Column("delivery_state", sa.String(length=12), server_default="sent", nullable=False),
    )
    op.add_column(
        "email_action_tokens",
        sa.Column("delivery_attempts", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "email_action_tokens",
        sa.Column("next_delivery_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.add_column("email_action_tokens", sa.Column("delivery_lease_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("email_action_tokens", sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("email_action_tokens", sa.Column("last_delivery_error", sa.String(length=64), nullable=True))
    op.create_check_constraint(
        "ck_email_action_tokens_delivery_state",
        "email_action_tokens",
        "delivery_state IN ('pending', 'sending', 'sent', 'failed', 'cancelled')",
    )
    op.create_index(
        "ix_email_action_tokens_delivery",
        "email_action_tokens",
        ["delivery_state", "next_delivery_at"],
    )
    op.alter_column("email_action_tokens", "delivery_state", server_default="pending")
    op.alter_column("email_action_tokens", "delivery_attempts", server_default="0")


def downgrade() -> None:
    op.drop_index("ix_email_action_tokens_delivery", table_name="email_action_tokens")
    op.drop_constraint(
        "ck_email_action_tokens_delivery_state",
        "email_action_tokens",
        type_="check",
    )
    op.drop_column("email_action_tokens", "last_delivery_error")
    op.drop_column("email_action_tokens", "delivered_at")
    op.drop_column("email_action_tokens", "delivery_lease_until")
    op.drop_column("email_action_tokens", "next_delivery_at")
    op.drop_column("email_action_tokens", "delivery_attempts")
    op.drop_column("email_action_tokens", "delivery_state")
    op.drop_column("email_action_tokens", "delivery_ciphertext")
