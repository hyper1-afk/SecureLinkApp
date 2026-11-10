"""Add tenant-managed exact-host threat indicators."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0018_threat_indicators"
down_revision: Union[str, None] = "0017_domain_monitoring"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("source", sa.String(length=16), server_default="customer", nullable=False),
        sa.Column("note", sa.String(length=240), nullable=True),
        sa.Column("created_by_user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("source = 'customer'", name="ck_threat_indicators_source"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "hostname", name="uq_threat_indicators_org_hostname"),
    )
    op.create_index("ix_threat_indicators_org_hostname", "threat_indicators", ["organization_id", "hostname"])


def downgrade() -> None:
    op.drop_index("ix_threat_indicators_org_hostname", table_name="threat_indicators")
    op.drop_table("threat_indicators")
