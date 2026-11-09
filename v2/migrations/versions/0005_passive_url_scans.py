"""Add passive URL scan evidence and findings.

Revision ID: 0005_passive_url_scans
Revises: 0004_org_invitations
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_passive_url_scans"
down_revision: Union[str, None] = "0004_org_invitations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "url_scans",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("requested_by_user_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("display_url", sa.String(length=512), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("scheme", sa.String(length=5), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status = 'completed'", name="ck_url_scans_status"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_url_scans_id_organization"),
    )
    op.create_index(
        "ix_url_scans_organization_created",
        "url_scans",
        ["organization_id", "created_at"],
    )
    op.create_table(
        "scan_evidence",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("detector_version", sa.String(length=32), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scan_id", "organization_id"],
            ["url_scans.id", "url_scans.organization_id"],
            name="fk_scan_evidence_scan_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_scan_evidence_id_organization"),
    )
    op.create_index("ix_scan_evidence_scan", "scan_evidence", ["scan_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("evidence_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("detector_code", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_findings_severity",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scan_id", "organization_id"],
            ["url_scans.id", "url_scans.organization_id"],
            name="fk_findings_scan_organization",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["scan_evidence.id", "scan_evidence.organization_id"],
            name="fk_findings_evidence_organization",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "detector_code", name="uq_findings_scan_detector"),
    )
    op.create_index("ix_findings_organization_created", "findings", ["organization_id", "created_at"])
    op.create_index("ix_findings_scan", "findings", ["scan_id"])
    op.execute("""
        CREATE FUNCTION reject_scan_evidence_mutation() RETURNS trigger
        LANGUAGE plpgsql AS 'BEGIN
            RAISE EXCEPTION ''scan evidence is immutable'';
        END;'
    """)
    op.execute("""
        CREATE TRIGGER scan_evidence_immutable
        BEFORE UPDATE OR DELETE ON scan_evidence
        FOR EACH ROW EXECUTE FUNCTION reject_scan_evidence_mutation()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER scan_evidence_immutable ON scan_evidence")
    op.execute("DROP FUNCTION reject_scan_evidence_mutation()")
    op.drop_index("ix_findings_scan", table_name="findings")
    op.drop_index("ix_findings_organization_created", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scan_evidence_scan", table_name="scan_evidence")
    op.drop_table("scan_evidence")
    op.drop_index("ix_url_scans_organization_created", table_name="url_scans")
    op.drop_table("url_scans")
