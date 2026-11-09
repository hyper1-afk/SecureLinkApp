"""Add email verification and password reset state.

Revision ID: 0002_email_account_lifecycle
Revises: 0001_identity_tenancy
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_email_account_lifecycle"
down_revision: Union[str, None] = "0001_identity_tenancy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email_verified", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), server_default="0", nullable=False),
    )
    op.create_table(
        "email_action_tokens",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("purpose", sa.String(length=24), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('verify_email', 'reset_password')",
            name="ck_email_action_tokens_purpose",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_email_action_tokens_hash"),
    )
    op.create_index("ix_email_action_tokens_user_id", "email_action_tokens", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_email_action_tokens_user_id", table_name="email_action_tokens")
    op.drop_table("email_action_tokens")
    op.drop_column("users", "token_version")
    op.drop_column("users", "email_verified")
