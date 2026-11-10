"""Store encrypted TOTP credentials and single-use recovery code digests.

Revision ID: 0010_account_mfa
Revises: 0009_invited_user_setup
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_account_mfa"
down_revision: Union[str, None] = "0009_invited_user_setup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret_ciphertext", sa.LargeBinary(), nullable=True))
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column("users", sa.Column("mfa_enrollment_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Uuid(as_uuid=False), primary_key=True),
        sa.Column("user_id", sa.Uuid(as_uuid=False), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_codes_user_hash"),
    )
    op.create_index("ix_mfa_recovery_codes_user_unused", "mfa_recovery_codes", ["user_id", "consumed_at"])


def downgrade() -> None:
    op.drop_index("ix_mfa_recovery_codes_user_unused", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_column("users", "mfa_enrollment_expires_at")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret_ciphertext")
