"""Add organization invitation action tokens.

Revision ID: 0004_org_invitations
Revises: 0003_email_outbox_delivery
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_org_invitations"
down_revision: Union[str, None] = "0003_email_outbox_delivery"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Invitation tokens cannot survive a downgrade to the old purpose constraint.
    op.execute("DELETE FROM email_action_tokens WHERE purpose = 'invite_member'")
    op.drop_constraint("ck_email_action_tokens_purpose", "email_action_tokens", type_="check")
    op.create_check_constraint(
        "ck_email_action_tokens_purpose",
        "email_action_tokens",
        "purpose IN ('verify_email', 'reset_password', 'invite_member')",
    )
    op.add_column("email_action_tokens", sa.Column("organization_id", sa.Uuid(as_uuid=False), nullable=True))
    op.create_foreign_key(
        "fk_email_action_tokens_organization_id_organizations",
        "email_action_tokens", "organizations", ["organization_id"], ["id"], ondelete="CASCADE"
    )
    op.create_index("ix_email_action_tokens_organization_id", "email_action_tokens", ["organization_id"])
    op.add_column("email_action_tokens", sa.Column("requested_role", sa.String(length=16), nullable=True))
    op.create_check_constraint(
        "ck_email_action_tokens_requested_role",
        "email_action_tokens",
        "requested_role IS NULL OR requested_role IN ('owner', 'admin', 'analyst', 'viewer')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_email_action_tokens_requested_role", "email_action_tokens", type_="check")
    op.drop_column("email_action_tokens", "requested_role")
    op.drop_index("ix_email_action_tokens_organization_id", table_name="email_action_tokens")
    op.drop_constraint(
        "fk_email_action_tokens_organization_id_organizations",
        "email_action_tokens",
        type_="foreignkey",
    )
    op.drop_column("email_action_tokens", "organization_id")
    op.drop_constraint("ck_email_action_tokens_purpose", "email_action_tokens", type_="check")
    op.create_check_constraint(
        "ck_email_action_tokens_purpose",
        "email_action_tokens",
        "purpose IN ('verify_email', 'reset_password')",
    )
