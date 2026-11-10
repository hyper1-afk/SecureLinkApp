"""Add pending authenticator rotation state."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0013_mfa_rotation"
down_revision: Union[str, None] = "0012_privileged_mfa_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_rotation_secret_ciphertext", sa.LargeBinary(), nullable=True))
    op.add_column("users", sa.Column("mfa_rotation_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_rotation_expires_at")
    op.drop_column("users", "mfa_rotation_secret_ciphertext")
