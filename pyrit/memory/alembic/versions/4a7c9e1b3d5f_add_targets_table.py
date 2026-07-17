# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Add persisted target configurations.

Revision ID: 4a7c9e1b3d5f
Revises: 3f6e8a0c2d4b
Create Date: 2026-07-17 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4a7c9e1b3d5f"
down_revision: str | None = "3f6e8a0c2d4b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the Targets table."""
    op.create_table(
        "Targets",
        sa.Column("target_registry_name", sa.String(), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=False),
        sa.Column("model_name", sa.String(), nullable=False),
        sa.Column("auth_mode", sa.String(), nullable=False),
        sa.Column("api_key_secret_uri", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("target_registry_name"),
    )


def downgrade() -> None:
    """Drop the Targets table."""
    op.drop_table("Targets")
