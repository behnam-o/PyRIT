# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import logging
from pathlib import Path

from alembic import command
from alembic.autogenerate.api import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
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
    table_names = set(inspect(connection).get_table_names())
    if _MEMORY_ALEMBIC_VERSION_TABLE in table_names:
        return

    if not _MEMORY_TABLES.intersection(table_names):
        return

    try:
        migration_context = MigrationContext.configure(connection=connection, opts={"compare_type": True})
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
    script_location = Path(__file__).with_name("alembic")
    logger.debug("Applying Alembic migrations from %s", script_location)
    with engine.begin() as connection:
        config = _make_config(connection=connection)
        _validate_and_stamp_unversioned_memory_schema(config=config, connection=connection)
        command.upgrade(config, _HEAD_REVISION)


def reset_schema(*, engine: Engine) -> None:
    """
    Recreate the database schema at the latest Alembic revision.

    Args:
        engine (Engine): SQLAlchemy engine bound to the target database.
    """
    logger.debug("Resetting memory schema using Alembic migrations")
    with engine.begin() as connection:
        Base.metadata.drop_all(connection)

        inspector = inspect(connection)
        if _MEMORY_ALEMBIC_VERSION_TABLE in inspector.get_table_names():
            connection.execute(text(f'DROP TABLE "{_MEMORY_ALEMBIC_VERSION_TABLE}"'))

        command.upgrade(_make_config(connection=connection), _HEAD_REVISION)
