# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest
from sqlalchemy.dialects import mssql, sqlite
from sqlalchemy.orm import Session

from pyrit.memory import MemoryInterface
from pyrit.memory.memory_models import SeedEntry
from pyrit.models import SeedPrompt, SeedSimulatedConversation


@pytest.mark.usefixtures("patch_central_database")
class TestSeedEntriesPage:
    @pytest.mark.parametrize(("offset", "expected_ids"), [(0, [1, 2]), (2, [3]), (3, []), (100, [])])
    async def test_seed_entries_page_order_and_total_async(
        self, *, sqlite_instance: MemoryInterface, offset: int, expected_ids: list[int]
    ) -> None:
        seeds = [
            SeedPrompt(
                id=UUID(int=seed_id),
                value=f"Seed {seed_id}",
                data_type="text",
                dataset_name="loaded",
                date_added=datetime(2026, 1, 1, tzinfo=UTC),
            )
            for seed_id in [3, 1, 2]
        ]
        seeds.append(SeedPrompt(id=UUID(int=4), value="Other seed", data_type="text", dataset_name="other"))
        await sqlite_instance.add_seeds_to_memory_async(seeds=seeds, added_by="test")

        entries, total = sqlite_instance.get_seed_entries_page(dataset_name="loaded", limit=2, offset=offset)
        repeated, repeated_total = sqlite_instance.get_seed_entries_page(dataset_name="loaded", limit=2, offset=offset)

        assert [entry.id for entry in entries] == [UUID(int=value) for value in expected_ids]
        assert [entry.id for entry in repeated] == [entry.id for entry in entries]
        assert total == repeated_total == 3

    @pytest.mark.parametrize("dataset_name", ["%_ /?'", " padded ", "not-loaded"])
    async def test_seed_entries_page_matches_exact_dataset_async(
        self, *, sqlite_instance: MemoryInterface, dataset_name: str
    ) -> None:
        seeds = [
            SeedPrompt(value=name, data_type="text", dataset_name=name)
            for name in ["%_ /?'", " padded ", "padded", "another"]
        ]
        await sqlite_instance.add_seeds_to_memory_async(seeds=seeds, added_by="test")

        entries, total = sqlite_instance.get_seed_entries_page(dataset_name=dataset_name, limit=25)

        expected_count = 0 if dataset_name == "not-loaded" else 1
        assert total == len(entries) == expected_count
        assert all(entry.dataset_name == dataset_name for entry in entries)

    @pytest.mark.parametrize(
        ("dataset_name", "limit", "offset"),
        [("", 25, 0), (" \t", 25, 0), ("loaded", 0, 0), ("loaded", -1, 0), ("loaded", 25, -1)],
    )
    def test_seed_entries_page_rejects_invalid_bounds(
        self, *, sqlite_instance: MemoryInterface, dataset_name: str, limit: int, offset: int
    ) -> None:
        with patch.object(sqlite_instance, "get_session") as get_session:
            with pytest.raises(ValueError):
                sqlite_instance.get_seed_entries_page(dataset_name=dataset_name, limit=limit, offset=offset)

        get_session.assert_not_called()

    def test_seed_entries_page_limits_sql_for_both_dialects(self, sqlite_instance: MemoryInterface) -> None:
        session = MagicMock(spec=Session)
        session.execute.return_value.scalar_one.return_value = 7
        session.execute.return_value.scalars.return_value.all.return_value = []
        with patch.object(sqlite_instance, "get_session", return_value=session):
            entries, total = sqlite_instance.get_seed_entries_page(dataset_name="loaded", limit=2, offset=3)

        assert entries == []
        assert total == 7
        assert session.execute.call_count == 2
        count_statement = session.execute.call_args_list[0].args[0]
        page_statement = session.execute.call_args_list[1].args[0]
        sqlite_sql = str(page_statement.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
        mssql_sql = str(page_statement.compile(dialect=mssql.dialect(), compile_kwargs={"literal_binds": True}))
        count_sql = str(count_statement.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
        assert 'ORDER BY "SeedPromptEntries".id ASC' in sqlite_sql
        assert "LIMIT 2 OFFSET 3" in sqlite_sql
        assert "ROW_NUMBER() OVER (ORDER BY [SeedPromptEntries].id ASC)" in mssql_sql
        assert "mssql_rn > 3" in mssql_sql
        assert "mssql_rn <= 2 + 3" in mssql_sql
        assert "count(*)" in count_sql
        assert "dataset_name = 'loaded'" in sqlite_sql
        assert "dataset_name = 'loaded'" in count_sql
        session.close.assert_called_once()

    def test_seed_entries_page_preserves_simulated_value(self, sqlite_instance: MemoryInterface) -> None:
        seed = SeedSimulatedConversation(
            adversarial_chat_system_prompt_path=Path("unread.yaml"),
            dataset_name="loaded",
            added_by="test",
            pyrit_version="stored-version",
        )
        entry = SeedEntry(entry=seed)
        sqlite_instance._insert_entries(entries=[entry])

        with patch.object(SeedEntry, "get_seed", side_effect=AssertionError("Seeds must not be reconstructed")):
            entries, total = sqlite_instance.get_seed_entries_page(dataset_name="loaded", limit=25)

        assert total == 1
        assert entries[0].value == seed.value
        assert entries[0].seed_type == "simulated_conversation"
        assert entries[0].sequence is None
