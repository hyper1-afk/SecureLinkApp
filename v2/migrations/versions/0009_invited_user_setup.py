"""Track accounts created through organization invitations.

Revision ID: 0009_invited_user_setup
Revises: 0008_extension_oauth
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_invited_user_setup"
down_revision: Union[str, None] = "0008_extension_oauth"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "invitation_setup_required",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "invitation_setup_required")
