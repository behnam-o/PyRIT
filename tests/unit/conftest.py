# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import asyncio
import inspect as inspect_module
import os
import tempfile
from collections.abc import Generator
from unittest.mock import patch

import pytest
from sqlalchemy import inspect

from pyrit.memory.central_memory import CentralMemory
from pyrit.memory.sqlite_memory import SQLiteMemory


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "probabilistic(runs, min_pass_rate): run the test body `runs` times and "
        "pass only if the fraction of successful runs is at least `min_pass_rate`. "
        "The whole thing is reported as a single test.",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function):
    """Run tests marked ``probabilistic`` multiple times and apply a pass-rate threshold.

    Returning a truthy value short-circuits pytest's default call, so the many
    trials collapse into a single reported test whose outcome (and therefore the
    process exit code) reflects the threshold.
    """
    marker = pyfuncitem.get_closest_marker("probabilistic")
    if marker is None:
        return None

    runs: int = marker.kwargs.get("runs", 100)
    min_pass_rate: float = marker.kwargs.get("min_pass_rate", 0.5)

    testfunction = pyfuncitem.obj
    testargs = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    is_async = inspect_module.iscoroutinefunction(testfunction)

    passes = 0
    for _ in range(runs):
        try:
            if is_async:
                asyncio.run(testfunction(**testargs))
            else:
                testfunction(**testargs)
            passes += 1
        except AssertionError:
            pass

    pass_rate = passes / runs
    if pass_rate < min_pass_rate:
        pytest.fail(
            f"Probabilistic test failed: {passes}/{runs} runs passed "
            f"(rate {pass_rate:.2%} < required {min_pass_rate:.2%})",
            pytrace=False,
        )

    return True

# This limits retries and speeds up execution
os.environ["CUSTOM_RESULT_RETRY_MAX_NUM_ATTEMPTS"] = "5"
os.environ["RETRY_MAX_NUM_ATTEMPTS"] = "2"
os.environ["RETRY_WAIT_MIN_SECONDS"] = "0"
os.environ["RETRY_WAIT_MAX_SECONDS"] = "1"


@pytest.fixture
def sqlite_instance() -> Generator[SQLiteMemory, None, None]:
    # Create an in-memory SQLite engine
    sqlite_memory = SQLiteMemory(db_path=":memory:")
    temp_dir = tempfile.TemporaryDirectory()
    sqlite_memory.results_path = temp_dir.name

    sqlite_memory.disable_embedding()

    # Reset the database to ensure a clean state
    sqlite_memory.reset_database()
    inspector = inspect(sqlite_memory.engine)

    # Verify that tables are created as expected
    assert "PromptMemoryEntries" in inspector.get_table_names(), "PromptMemoryEntries table not created."
    assert "EmbeddingData" in inspector.get_table_names(), "EmbeddingData table not created."
    assert "ScoreEntries" in inspector.get_table_names(), "ScoreEntries table not created."
    assert "SeedPromptEntries" in inspector.get_table_names(), "SeedPromptEntries table not created."

    CentralMemory.set_memory_instance(sqlite_memory)
    yield sqlite_memory
    temp_dir.cleanup()
    sqlite_memory.dispose_engine()


@pytest.fixture()
def patch_central_database(sqlite_instance):
    """Fixture to mock CentralMemory.get_memory_instance"""
    with patch.object(CentralMemory, "get_memory_instance", return_value=sqlite_instance) as sqlite_memory:
        yield sqlite_memory
