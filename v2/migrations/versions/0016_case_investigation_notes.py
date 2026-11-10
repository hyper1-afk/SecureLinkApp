"""Add append-only tenant-scoped investigation notes to cases."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0016_case_notes"
down_revision: Union[str, None] = "0015_security_signals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "case_notes",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_notes_case_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("length(content) BETWEEN 1 AND 4000", name="ck_case_notes_content_length"),
    )
    op.create_index("ix_case_notes_case_created", "case_notes", ["case_id", "created_at"])
    op.execute("""
        CREATE FUNCTION reject_case_note_mutation() RETURNS trigger
        LANGUAGE plpgsql AS 'BEGIN
            RAISE EXCEPTION ''case notes are immutable'';
        END;'
    """)
    op.execute("""
        CREATE TRIGGER case_notes_immutable
        BEFORE UPDATE OR DELETE ON case_notes
        FOR EACH ROW EXECUTE FUNCTION reject_case_note_mutation()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER case_notes_immutable ON case_notes")
    op.execute("DROP FUNCTION reject_case_note_mutation()")
    op.drop_index("ix_case_notes_case_created", table_name="case_notes")
    op.drop_table("case_notes")
