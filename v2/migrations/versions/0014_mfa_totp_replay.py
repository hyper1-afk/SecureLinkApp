"""Track the last accepted TOTP time step per user."""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0014_mfa_totp_replay"
down_revision: Union[str, None] = "0013_mfa_rotation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_last_totp_step", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_last_totp_step")
