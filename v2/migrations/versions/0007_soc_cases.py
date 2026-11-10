"""Add tenant-scoped SOC cases and finding links.

Revision ID: 0007_soc_cases
Revises: 0006_verified_domain_assets
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_soc_cases"
down_revision: Union[str, None] = "0006_verified_domain_assets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_cases",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("status", sa.String(length=24), server_default="open", nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('open', 'investigating', 'awaiting_approval', 'resolved', 'false_positive')",
            name="ck_incident_cases_status",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_incident_cases_severity",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["scan_id", "organization_id"],
            ["url_scans.id", "url_scans.organization_id"],
            name="fk_incident_cases_scan_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_incident_cases_id_organization"),
        sa.UniqueConstraint("scan_id", "organization_id", name="uq_incident_cases_scan_organization"),
    )
    op.create_index(
        "ix_incident_cases_org_status_created",
        "incident_cases",
        ["organization_id", "status", "created_at"],
    )
    op.create_table(
        "case_findings",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("finding_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_findings_case_organization",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_case_findings_finding_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "finding_id", name="uq_case_findings_case_finding"),
        sa.UniqueConstraint("finding_id", "organization_id", name="uq_case_findings_finding_organization"),
    )
    op.create_index("ix_case_findings_case", "case_findings", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_case_findings_case", table_name="case_findings")
    op.drop_table("case_findings")
    op.drop_index("ix_incident_cases_org_status_created", table_name="incident_cases")
    op.drop_table("incident_cases")
