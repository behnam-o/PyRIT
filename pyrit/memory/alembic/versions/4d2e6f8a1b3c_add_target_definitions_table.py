# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Add persisted target definitions for DB-backed target registration.

Creates ``TargetDefinitions`` to store durable target configuration descriptors
that can be loaded by ``TargetInitializer`` and instantiated into runtime
targets.

Revision ID: 4d2e6f8a1b3c
Revises: c3d5e7f9a1b2
Create Date: 2026-06-15 11:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from pyrit.memory.memory_models import CustomUUID

# revision identifiers, used by Alembic.
revision: str = "4d2e6f8a1b3c"
down_revision: str | None = "c3d5e7f9a1b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply this schema upgrade."""
    op.create_table(
        "TargetDefinitions",
        sa.Column("id", CustomUUID(), nullable=False, primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("target_type", sa.String(), nullable=False),
        sa.Column("endpoint", sa.Unicode(), nullable=False),
        sa.Column("model_name", sa.String(), nullable=True),
        sa.Column("underlying_model", sa.String(), nullable=True),
        sa.Column("temperature", sa.Float(), nullable=True),
        sa.Column("extra_kwargs", sa.JSON(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("is_enabled", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_default_objective_target", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("auth_mode", sa.String(), nullable=False, server_default="api_key"),
        sa.Column("api_key_env_var", sa.String(), nullable=True),
    )
    op.create_index("ix_target_definitions_name", "TargetDefinitions", ["name"], unique=True)


def downgrade() -> None:
    """Revert this schema upgrade."""
    op.drop_index("ix_target_definitions_name", table_name="TargetDefinitions")
    op.drop_table("TargetDefinitions")