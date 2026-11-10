"""Add opt-in domain DNS monitoring state."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0017_domain_monitoring"
down_revision: Union[str, None] = "0016_case_notes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "domain_assets",
        sa.Column("monitoring_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.create_unique_constraint(
        "uq_domain_assets_id_organization", "domain_assets", ["id", "organization_id"]
    )
    op.create_table(
        "domain_monitor_states",
        sa.Column("asset_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("monitor_type", sa.String(length=64), nullable=False),
        sa.Column("current_state", sa.Text(), server_default="{}", nullable=False),
        sa.Column("generation", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=64), nullable=True),
        sa.CheckConstraint("generation >= 0", name="ck_domain_monitor_states_generation"),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["domain_assets.id", "domain_assets.organization_id"],
            name="fk_domain_monitor_states_asset_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("asset_id", "organization_id", "monitor_type"),
    )
    op.create_index(
        "ix_domain_monitor_states_due",
        "domain_monitor_states",
        ["next_check_at", "lease_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_domain_monitor_states_due", table_name="domain_monitor_states")
    op.drop_table("domain_monitor_states")
    op.drop_constraint("uq_domain_assets_id_organization", "domain_assets", type_="unique")
    op.drop_column("domain_assets", "monitoring_enabled")
