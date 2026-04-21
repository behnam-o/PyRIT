# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import logging
from pathlib import Path

from alembic import command
from alembic.autogenerate.api import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import MetaData, Table, inspect
from sqlalchemy.engine import Connection, Engine

from pyrit.memory.memory_models import Base

logger = logging.getLogger(__name__)

_MEMORY_ALEMBIC_VERSION_TABLE = "pyrit_memory_alembic_version"
_HEAD_REVISION = "head"
_INITIAL_MEMORY_REVISION = "e373726d391b"
_MEMORY_TABLES = {
    "AttackResultEntries",
    "EmbeddingData",
    "PromptMemoryEntries",
    "ScenarioResultEntries",
    "ScoreEntries",
    "SeedPromptEntries",
}


def _include_name_for_memory_schema(
    name: str | None,
    type_: str,
    parent_names: dict[str, str],
) -> bool:
    """
    Restrict schema comparisons to PyRIT memory tables and their child objects.

    Args:
        name (str | None): Name of the database object being considered.
        type_ (str): SQLAlchemy object type (e.g., "table", "column", "index").
        parent_names (dict[str, str]): Parent-name context provided by Alembic.

    Returns:
        bool: True when the object should be included in schema comparison.
    """
    if type_ == "table":
        return bool(name and name in _MEMORY_TABLES)

    table_name = parent_names.get("table_name")
    if table_name:
        return table_name in _MEMORY_TABLES

    return True


def _make_config(*, connection: Connection) -> Config:
    """
    Build an Alembic config for the memory migration scripts.

    Args:
        connection (Connection): Database connection for Alembic commands.

    Returns:
        Config: Configured Alembic config object.
    """
    script_location = Path(__file__).with_name("alembic")

    config = Config()
    config.set_main_option("script_location", str(script_location))
    config.attributes["connection"] = connection
    config.attributes["version_table"] = _MEMORY_ALEMBIC_VERSION_TABLE
    return config


def _validate_and_stamp_unversioned_memory_schema(*, config: Config, connection: Connection) -> None:
    """
    Validate and stamp unversioned legacy memory schemas.

    Args:
        config (Config): Alembic config bound to the current connection.
        connection (Connection): Database connection to inspect.

    Raises:
        RuntimeError: If an unversioned memory schema does not match models.
    """
    # Perform all inspection in one atomic call to avoid race conditions
    inspector = inspect(connection)
    table_names = set(inspector.get_table_names())

    # If version table already exists, migration has been stamped
    if _MEMORY_ALEMBIC_VERSION_TABLE in table_names:
        return

    # If no memory tables exist, this is a fresh database
    if not _MEMORY_TABLES.intersection(table_names):
        return

    # Unversioned memory schema detected; validate it matches current models
    try:
        migration_context = MigrationContext.configure(
            connection=connection,
            opts={"compare_type": True, "include_name": _include_name_for_memory_schema},
        )
        diffs = compare_metadata(migration_context, Base.metadata)
    except Exception as e:
        raise RuntimeError(
            "Detected an unversioned legacy memory schema (memory tables exist, but "
            "pyrit_memory_alembic_version is missing), "
            "and it does not match current models. Repair or rebuild the database before upgrading to this release."
        ) from e

    if diffs:
        raise RuntimeError(
            "Detected an unversioned legacy memory schema (memory tables exist, but "
            "pyrit_memory_alembic_version is missing), "
            "and it does not match current models. Repair or rebuild the database before upgrading to this release."
        )

    logger.info("Detected matching unversioned memory schema; stamping revision %s", _INITIAL_MEMORY_REVISION)
    command.stamp(config, _INITIAL_MEMORY_REVISION)


def run_schema_migrations(*, engine: Engine) -> None:
    """
    Upgrade the database schema to the latest Alembic revision.

    Args:
        engine (Engine): SQLAlchemy engine bound to the target database.

    Raises:
        Exception: If Alembic fails to apply migrations.
    """
    with engine.begin() as connection:
        config = _make_config(connection=connection)
        _validate_and_stamp_unversioned_memory_schema(config=config, connection=connection)
        command.upgrade(config, _HEAD_REVISION)


def reset_database(*, engine: Engine) -> None:
    """
    Drop all tables and recreate the database schema at the latest Alembic revision.

    This destroys all existing data.

    Args:
        engine (Engine): SQLAlchemy engine bound to the target database.
    """
    logger.debug("Resetting database using Alembic migrations")
    with engine.begin() as connection:
        # Drop version table first (not part of Base.metadata)
        inspector = inspect(connection)
        if _MEMORY_ALEMBIC_VERSION_TABLE in inspector.get_table_names():
            version_table = Table(_MEMORY_ALEMBIC_VERSION_TABLE, MetaData(), autoload_with=connection)
            version_table.drop(connection)

        # Drop all application tables defined in models
        Base.metadata.drop_all(connection)

        # Rebuild schema from migrations
        command.upgrade(_make_config(connection=connection), _HEAD_REVISION)
