"""Add tenant-scoped, human-reviewed case approval records."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0019_case_approvals"
down_revision: Union[str, None] = "0018_threat_indicators"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "case_approvals",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("rationale", sa.String(length=1000), nullable=False),
        sa.Column("status", sa.String(length=12), server_default="pending", nullable=False),
        sa.Column("requester_user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("reviewer_user_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("decision_note", sa.String(length=1000), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "action IN ('disable_domain_monitoring', 'disable_threat_indicator', 'revoke_extension_sessions')",
            name="ck_case_approvals_action",
        ),
        sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'expired')", name="ck_case_approvals_status"),
        sa.CheckConstraint("requester_user_id <> reviewer_user_id", name="ck_case_approvals_no_self_review"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requester_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewer_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_approvals_case_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_case_approvals_one_pending_per_case",
        "case_approvals",
        ["case_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
        sqlite_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_case_approvals_case_created",
        "case_approvals",
        ["case_id", "created_at"],
    )
    op.create_index(
        "ix_case_approvals_org_status_created",
        "case_approvals",
        ["organization_id", "status", "created_at"],
    )
    op.execute("""
        CREATE FUNCTION guard_case_approval_mutation() RETURNS trigger
        LANGUAGE plpgsql AS 'BEGIN
            IF TG_OP = ''DELETE'' THEN
                RAISE EXCEPTION ''case approvals cannot be deleted'';
            END IF;
            IF OLD.status <> ''pending''
               OR NEW.status NOT IN (''approved'', ''rejected'', ''expired'')
               OR NEW.id <> OLD.id
               OR NEW.organization_id <> OLD.organization_id
               OR NEW.case_id <> OLD.case_id
               OR NEW.action <> OLD.action
               OR NEW.rationale <> OLD.rationale
               OR NEW.requester_user_id <> OLD.requester_user_id
               OR NEW.expires_at <> OLD.expires_at
               OR NEW.created_at <> OLD.created_at
               OR (NEW.reviewer_user_id IS NULL AND NEW.status <> ''expired'')
               OR NEW.decided_at IS NULL THEN
                RAISE EXCEPTION ''case approval allows one audited decision only'';
            END IF;
            RETURN NEW;
        END;'
    """)
    op.execute("""
        CREATE TRIGGER case_approvals_one_way_decision
        BEFORE UPDATE OR DELETE ON case_approvals
        FOR EACH ROW EXECUTE FUNCTION guard_case_approval_mutation()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER case_approvals_one_way_decision ON case_approvals")
    op.execute("DROP FUNCTION guard_case_approval_mutation()")
    op.drop_index("ix_case_approvals_org_status_created", table_name="case_approvals")
    op.drop_index("ix_case_approvals_case_created", table_name="case_approvals")
    op.drop_index("uq_case_approvals_one_pending_per_case", table_name="case_approvals")
    op.drop_table("case_approvals")
