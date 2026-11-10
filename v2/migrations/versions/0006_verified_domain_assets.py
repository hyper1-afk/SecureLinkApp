"""Add tenant-scoped domain inventory and ownership verification state.

Revision ID: 0006_verified_domain_assets
Revises: 0005_passive_url_scans
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_verified_domain_assets"
down_revision: Union[str, None] = "0005_passive_url_scans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "domain_assets",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("status", sa.String(length=12), server_default="pending", nullable=False),
        sa.Column("verification_token_hash", sa.String(length=64), nullable=True),
        sa.Column("verification_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('pending', 'verified')", name="ck_domain_assets_status"),
        sa.CheckConstraint(
            "(status = 'pending' AND verification_token_hash IS NOT NULL "
            "AND verification_expires_at IS NOT NULL AND verified_at IS NULL) OR "
            "(status = 'verified' AND verification_token_hash IS NULL "
            "AND verification_expires_at IS NULL AND verified_at IS NOT NULL)",
            name="ck_domain_assets_verification_state",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "hostname", name="uq_domain_assets_org_hostname"),
    )
    op.create_index("ix_domain_assets_org_status", "domain_assets", ["organization_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_domain_assets_org_status", table_name="domain_assets")
    op.drop_table("domain_assets")
