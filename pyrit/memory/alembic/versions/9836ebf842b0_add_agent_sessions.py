# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Add agent sessions.

Creates ``AgentSessionEntries``, which lists saved agent chats. A session's messages are
the conversation whose ID is the session ID, so no existing table changes.

Revision ID: 9836ebf842b0
Revises: a3f7c9e2b641
Create Date: 2026-11-16 12:00:00.000000
"""

from collections.abc import Sequence  # noqa: TC003

import sqlalchemy as sa
from alembic import op

from pyrit.memory.memory_models import CustomUUID, UTCDateTime

# revision identifiers, used by Alembic.
revision: str = "9836ebf842b0"
down_revision: str | None = "a3f7c9e2b641"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the agent session table."""
    op.create_table(
        "AgentSessionEntries",
        sa.Column("id", CustomUUID(), primary_key=True),
        sa.Column("title", sa.Unicode(256), nullable=False),
        sa.Column("target_registry_name", sa.Unicode(256), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
    )


def downgrade() -> None:
    """Drop the agent session table. The sessions' conversations stay in memory."""
    op.drop_table("AgentSessionEntries")
