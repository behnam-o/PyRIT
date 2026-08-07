# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Add stable ids and display names to persisted target configurations.

Revision ID: 6b8d0f2a4c7e
Revises: 4a7c9e1b3d5f
Create Date: 2026-08-07 00:00:00.000000
"""

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6b8d0f2a4c7e"
down_revision: str | None = "4a7c9e1b3d5f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Replace registry-name identity with stable ids and display names."""
    connection = op.get_bind()
    existing_rows = list(
        connection.execute(
            sa.text(
                "SELECT target_registry_name, endpoint, model_name, auth_mode, api_key_secret_uri FROM Targets"
            )
        ).mappings()
    )

    op.create_table(
        "Targets_v2",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=False),
        sa.Column("model_name", sa.String(), nullable=False),
        sa.Column("auth_mode", sa.String(), nullable=False),
        sa.Column("api_key_secret_uri", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    targets_v2 = sa.table(
        "Targets_v2",
        sa.column("id", sa.String(length=36)),
        sa.column("display_name", sa.String(length=255)),
        sa.column("endpoint", sa.String()),
        sa.column("model_name", sa.String()),
        sa.column("auth_mode", sa.String()),
        sa.column("api_key_secret_uri", sa.String()),
    )
    op.bulk_insert(
        targets_v2,
        [
            {
                "id": str(uuid4()),
                "display_name": row["target_registry_name"],
                "endpoint": row["endpoint"],
                "model_name": row["model_name"],
                "auth_mode": row["auth_mode"],
                "api_key_secret_uri": row["api_key_secret_uri"],
            }
            for row in existing_rows
        ],
    )
    op.drop_table("Targets")
    op.rename_table("Targets_v2", "Targets")


def downgrade() -> None:
    """Restore registry-name identity using display names as unique aliases."""
    connection = op.get_bind()
    existing_rows = list(
        connection.execute(
            sa.text("SELECT id, display_name, endpoint, model_name, auth_mode, api_key_secret_uri FROM Targets")
        ).mappings()
    )

    op.create_table(
        "Targets_v1",
        sa.Column("target_registry_name", sa.String(length=512), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=False),
        sa.Column("model_name", sa.String(), nullable=False),
        sa.Column("auth_mode", sa.String(), nullable=False),
        sa.Column("api_key_secret_uri", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("target_registry_name"),
    )
    targets_v1 = sa.table(
        "Targets_v1",
        sa.column("target_registry_name", sa.String(length=512)),
        sa.column("endpoint", sa.String()),
        sa.column("model_name", sa.String()),
        sa.column("auth_mode", sa.String()),
        sa.column("api_key_secret_uri", sa.String()),
    )
    op.bulk_insert(
        targets_v1,
        [
            {
                "target_registry_name": f"{row['display_name']}-{row['id']}",
                "endpoint": row["endpoint"],
                "model_name": row["model_name"],
                "auth_mode": row["auth_mode"],
                "api_key_secret_uri": row["api_key_secret_uri"],
            }
            for row in existing_rows
        ],
    )
    op.drop_table("Targets")
    op.rename_table("Targets_v1", "Targets")
