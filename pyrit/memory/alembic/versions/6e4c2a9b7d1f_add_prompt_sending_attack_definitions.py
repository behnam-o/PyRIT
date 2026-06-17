# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Add persisted prompt-sending attack and base64 converter definitions.

Creates:
- ``Base64ConverterDefinitions``
- ``PromptSendingAttackDefinitions``
- ``PromptSendingAttackTargetDefinitionRefs``
- ``PromptSendingAttackConverterDefinitionRefs``

Revision ID: 6e4c2a9b7d1f
Revises: 4d2e6f8a1b3c
Create Date: 2026-06-16 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from pyrit.memory.memory_models import CustomUUID

# revision identifiers, used by Alembic.
revision: str = "6e4c2a9b7d1f"
down_revision: str | None = "4d2e6f8a1b3c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply this schema upgrade."""
    op.create_table(
        "Base64ConverterDefinitions",
        sa.Column("id", CustomUUID(), nullable=False, primary_key=True),
        sa.Column("encoding_func", sa.String(), nullable=False),
    )

    op.create_table(
        "PromptSendingAttackDefinitions",
        sa.Column("id", CustomUUID(), nullable=False, primary_key=True),
    )

    op.create_table(
        "PromptSendingAttackTargetDefinitionRefs",
        sa.Column("prompt_sending_attack_definition_id", CustomUUID(), nullable=False, primary_key=True),
        sa.Column("target_definition_id", CustomUUID(), nullable=False),
        sa.ForeignKeyConstraint(
            ["prompt_sending_attack_definition_id"],
            ["PromptSendingAttackDefinitions.id"],
            name="fk_ps_attack_target_ref_attack",
        ),
        sa.ForeignKeyConstraint(
            ["target_definition_id"],
            ["TargetDefinitions.id"],
            name="fk_ps_attack_target_ref_target",
        ),
    )

    op.create_table(
        "PromptSendingAttackConverterDefinitionRefs",
        sa.Column("prompt_sending_attack_definition_id", CustomUUID(), nullable=False, primary_key=True),
        sa.Column("converter_definition_id", CustomUUID(), nullable=False, primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(
            ["prompt_sending_attack_definition_id"],
            ["PromptSendingAttackDefinitions.id"],
            name="fk_ps_attack_converter_ref_attack",
        ),
        sa.ForeignKeyConstraint(
            ["converter_definition_id"],
            ["Base64ConverterDefinitions.id"],
            name="fk_ps_attack_converter_ref_converter",
        ),
    )

    op.create_index(
        "ix_prompt_sending_attack_converter_ref_attack_id_position",
        "PromptSendingAttackConverterDefinitionRefs",
        ["prompt_sending_attack_definition_id", "position"],
        unique=True,
    )


def downgrade() -> None:
    """Revert this schema upgrade."""
    op.drop_index(
        "ix_prompt_sending_attack_converter_ref_attack_id_position",
        table_name="PromptSendingAttackConverterDefinitionRefs",
    )
    op.drop_table("PromptSendingAttackConverterDefinitionRefs")
    op.drop_table("PromptSendingAttackTargetDefinitionRefs")
    op.drop_table("PromptSendingAttackDefinitions")
    op.drop_table("Base64ConverterDefinitions")
