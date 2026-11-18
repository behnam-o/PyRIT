# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import importlib
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory

from pyrit.memory.migration import check_schema_migrations

REVISION = "9836ebf842b0"
MIGRATION = f"pyrit.memory.alembic.versions.{REVISION}_add_agent_sessions"


def test_agent_session_migration_creates_and_drops_only_its_table() -> None:
    migration = importlib.import_module(MIGRATION)
    engine = sa.create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as connection:
            operations = Operations(MigrationContext.configure(connection))
            with patch.object(migration, "op", operations):
                migration.upgrade()
                columns = {
                    column["name"]: column for column in sa.inspect(connection).get_columns("AgentSessionEntries")
                }
                migration.downgrade()
            assert sa.inspect(connection).get_table_names() == []
    finally:
        engine.dispose()

    assert set(columns) == {"id", "title", "target_registry_name", "created_at", "updated_at"}
    assert not any(column["nullable"] for column in columns.values())


def test_agent_session_migration_bounds_sql_server_text_columns() -> None:
    migration = importlib.import_module(MIGRATION)
    output = StringIO()
    context = MigrationContext.configure(dialect_name="mssql", opts={"as_sql": True, "output_buffer": output})
    with patch.object(migration, "op", Operations(context)):
        migration.upgrade()

    assert "title NVARCHAR(256) NOT NULL" in output.getvalue()
    assert "target_registry_name NVARCHAR(256) NOT NULL" in output.getvalue()


def test_agent_session_migration_has_unique_head_and_upgrades_its_parent() -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[3] / "pyrit" / "memory" / "alembic"))
    scripts = ScriptDirectory.from_config(config)
    assert len(scripts.get_heads()) == 1
    assert scripts.get_revision(REVISION).down_revision == "a3f7c9e2b641"
    engine = sa.create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as connection:
            config.attributes["connection"] = connection
            config.attributes["version_table"] = "pyrit_memory_alembic_version"
            command.upgrade(config, "a3f7c9e2b641")
            assert "AgentSessionEntries" not in sa.inspect(connection).get_table_names()
            command.upgrade(config, "head")
        check_schema_migrations(engine=engine)
    finally:
        engine.dispose()
