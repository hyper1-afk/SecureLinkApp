"""Store one global, expiring snapshot per approved threat feed.

Revision ID: 0020_threat_feed_snapshots
Revises: 0019_case_approvals
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0020_threat_feed_snapshots"
down_revision: Union[str, None] = "0019_case_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_feed_snapshots",
        sa.Column("feed_id", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint("feed_id <> ''", name="ck_threat_feed_snapshots_feed_id_nonempty"),
        sa.CheckConstraint("entry_count > 0", name="ck_threat_feed_snapshots_entry_count_positive"),
        sa.PrimaryKeyConstraint("feed_id"),
    )
    op.create_table(
        "threat_feed_sync_states",
        sa.Column("feed_id", sa.String(length=64), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=48), nullable=True),
        sa.PrimaryKeyConstraint("feed_id"),
    )


def downgrade() -> None:
    op.drop_table("threat_feed_sync_states")
    op.drop_table("threat_feed_snapshots")

