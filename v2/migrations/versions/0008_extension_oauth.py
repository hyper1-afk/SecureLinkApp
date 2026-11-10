"""Add PKCE authorization codes and revocable extension sessions.

Revision ID: 0008_extension_oauth
Revises: 0007_soc_cases
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_extension_oauth"
down_revision: Union[str, None] = "0007_soc_cases"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "extension_authorization_codes",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("code_challenge", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash", name="uq_extension_authorization_codes_hash"),
    )
    op.create_index(
        "ix_extension_authorization_codes_expiry",
        "extension_authorization_codes",
        ["expires_at"],
    )
    op.create_table(
        "extension_sessions",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_extension_sessions_token_hash"),
    )
    op.create_index(
        "ix_extension_sessions_user_org",
        "extension_sessions",
        ["user_id", "organization_id"],
    )
    op.create_index("ix_extension_sessions_expiry", "extension_sessions", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_extension_sessions_expiry", table_name="extension_sessions")
    op.drop_index("ix_extension_sessions_user_org", table_name="extension_sessions")
    op.drop_table("extension_sessions")
    op.drop_index("ix_extension_authorization_codes_expiry", table_name="extension_authorization_codes")
    op.drop_table("extension_authorization_codes")
