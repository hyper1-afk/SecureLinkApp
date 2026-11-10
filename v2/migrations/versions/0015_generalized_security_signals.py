"""Introduce tenant-scoped security signals and link cases to signals."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0015_security_signals"
down_revision: Union[str, None] = "0014_mfa_totp_replay"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_signals",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("source_type", sa.String(length=24), nullable=False),
        sa.Column("source_reference", sa.String(length=128), nullable=False),
        sa.Column("signal_type", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=253), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "source_type IN ('url_scan', 'extension_scan', 'domain_monitor', 'integration')",
            name="ck_security_signals_source_type",
        ),
        sa.CheckConstraint("signal_type <> ''", name="ck_security_signals_type_nonempty"),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_security_signals_severity",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "source_type", "source_reference", name="uq_security_signal_source"),
        sa.UniqueConstraint("id", "organization_id", name="uq_security_signals_id_organization"),
    )
    op.create_index(
        "ix_security_signals_org_observed", "security_signals", ["organization_id", "observed_at"]
    )
    op.execute(
        """
        INSERT INTO security_signals (
            id, organization_id, source_type, source_reference, signal_type, subject,
            severity, title, summary, observed_at, payload, content_hash, created_at
        )
        SELECT
            gen_random_uuid(), scans.organization_id, 'url_scan', scans.id::text,
            'passive_url_hygiene', scans.hostname,
            COALESCE((
                SELECT finding.severity
                FROM findings AS finding
                WHERE finding.organization_id = scans.organization_id
                  AND finding.scan_id = scans.id
                ORDER BY CASE finding.severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 ELSE 4 END
                LIMIT 1
            ), 'informational'),
            'URL hygiene scan observed',
            'Passive URL-structure analysis completed; this is not a safety verdict.',
            scans.created_at, evidence.payload, evidence.content_hash, scans.created_at
        FROM url_scans AS scans
        JOIN LATERAL (
            SELECT evidence.payload, evidence.content_hash
            FROM scan_evidence AS evidence
            WHERE evidence.organization_id = scans.organization_id
              AND evidence.scan_id = scans.id
            ORDER BY evidence.created_at, evidence.id
            LIMIT 1
        ) AS evidence ON TRUE
        """
    )

    op.create_table(
        "case_signals",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("signal_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_signals_case_organization",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["signal_id", "organization_id"],
            ["security_signals.id", "security_signals.organization_id"],
            name="fk_case_signals_signal_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "signal_id", name="uq_case_signals_case_signal"),
        sa.UniqueConstraint("signal_id", "organization_id", name="uq_case_signals_signal_organization"),
    )
    op.create_index("ix_case_signals_case", "case_signals", ["case_id"])
    op.create_index("ix_case_signals_signal", "case_signals", ["signal_id"])
    op.execute(
        """
        INSERT INTO case_signals (id, organization_id, case_id, signal_id)
        SELECT gen_random_uuid(), cases.organization_id, cases.id, signals.id
        FROM incident_cases AS cases
        JOIN security_signals AS signals
          ON signals.organization_id = cases.organization_id
         AND signals.source_type = 'url_scan'
         AND signals.source_reference = cases.scan_id::text
        """
    )
    op.alter_column("incident_cases", "scan_id", existing_type=sa.Uuid(as_uuid=False), nullable=True)
    op.execute("""
        CREATE FUNCTION reject_security_signal_mutation() RETURNS trigger
        LANGUAGE plpgsql AS 'BEGIN
            RAISE EXCEPTION ''security signals are immutable'';
        END;'
    """)
    op.execute("""
        CREATE TRIGGER security_signals_immutable
        BEFORE UPDATE OR DELETE ON security_signals
        FOR EACH ROW EXECUTE FUNCTION reject_security_signal_mutation()
    """)
    op.execute("""
        CREATE FUNCTION reject_case_signal_mutation() RETURNS trigger
        LANGUAGE plpgsql AS 'BEGIN
            RAISE EXCEPTION ''case signal links are immutable'';
        END;'
    """)
    op.execute("""
        CREATE TRIGGER case_signals_immutable
        BEFORE UPDATE OR DELETE ON case_signals
        FOR EACH ROW EXECUTE FUNCTION reject_case_signal_mutation()
    """)


def downgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM incident_cases WHERE scan_id IS NULL) THEN
                RAISE EXCEPTION 'cannot downgrade while cases exist without a URL scan';
            END IF;
        END $$
    """)
    op.alter_column("incident_cases", "scan_id", existing_type=sa.Uuid(as_uuid=False), nullable=False)
    op.execute("DROP TRIGGER case_signals_immutable ON case_signals")
    op.execute("DROP FUNCTION reject_case_signal_mutation()")
    op.execute("DROP TRIGGER security_signals_immutable ON security_signals")
    op.execute("DROP FUNCTION reject_security_signal_mutation()")
    op.drop_index("ix_case_signals_signal", table_name="case_signals")
    op.drop_index("ix_case_signals_case", table_name="case_signals")
    op.drop_table("case_signals")
    op.drop_index("ix_security_signals_org_observed", table_name="security_signals")
    op.drop_table("security_signals")
