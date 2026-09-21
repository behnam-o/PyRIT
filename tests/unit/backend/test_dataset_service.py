# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Tests for backend dataset service.
"""

import asyncio
from collections.abc import Generator
from threading import Event, get_ident
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from pyrit.backend.services.dataset_service import DatasetLoadError, DatasetService, get_dataset_service
from pyrit.datasets import SeedDatasetProvider
from pyrit.memory import MemoryInterface
from pyrit.memory.memory_models import SeedEntry
from pyrit.models import SeedDataset, SeedObjective, SeedPrompt
from pyrit.setup.initializers.load_default_datasets import LoadDefaultDatasets


@pytest.fixture
def mock_memory() -> MagicMock:
    """Create a mock memory instance."""
    memory = MagicMock(spec=MemoryInterface)
    memory.get_seed_dataset_names.return_value = []
    memory.get_seed_entries_page.return_value = ([], 0)
    return memory


@pytest.fixture
def dataset_service(mock_memory: MagicMock) -> Generator[DatasetService, None, None]:
    """Create a dataset service with mocked memory."""
    with patch("pyrit.backend.services.dataset_service.CentralMemory") as mock_central:
        mock_central.get_memory_instance.return_value = mock_memory
        yield DatasetService()


@pytest.fixture
def registered_provider() -> Generator[MagicMock, None, None]:
    provider = MagicMock(spec=SeedDatasetProvider)
    provider.dataset_name = "test_dataset"
    provider._parse_metadata_async.return_value = None
    provider.fetch_dataset_async.return_value = SeedDataset(
        seeds=[SeedObjective(value="A loaded objective", dataset_name="test_dataset")]
    )
    provider_class = MagicMock(return_value=provider)
    with (
        patch.object(SeedDatasetProvider, "_materialize_builtin_providers"),
        patch.dict(SeedDatasetProvider._registry, {"TestProvider": provider_class}, clear=True),
    ):
        yield provider


@pytest.mark.usefixtures("patch_central_database")
class TestListDatasets:
    """Tests for DatasetService.list_datasets_async."""

    async def test_list_datasets(self, dataset_service):
        with patch(
            "pyrit.backend.services.dataset_service.SeedDatasetProvider.get_all_dataset_names_async",
            new_callable=AsyncMock,
            return_value=["airt_hate", "harmbench"],
        ):
            result = await dataset_service.list_datasets_async()

        assert [item.name for item in result.items] == ["airt_hate", "harmbench"]

    async def test_list_datasets_empty(self, dataset_service):
        with patch(
            "pyrit.backend.services.dataset_service.SeedDatasetProvider.get_all_dataset_names_async",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await dataset_service.list_datasets_async()

        assert result.items == []

    async def test_list_datasets_combines_loaded_and_provider_names_async(
        self, *, dataset_service: DatasetService, mock_memory: MagicMock
    ) -> None:
        mock_memory.get_seed_dataset_names.return_value = ["loaded", "harmbench"]
        with patch(
            "pyrit.backend.services.dataset_service.SeedDatasetProvider.get_all_dataset_names_async",
            new_callable=AsyncMock,
            return_value=["harmbench", "airt_hate"],
        ):
            result = await dataset_service.list_datasets_async()

        assert result.model_dump() == {
            "items": [
                {"name": "airt_hate", "is_loaded": False, "can_load": True},
                {"name": "harmbench", "is_loaded": True, "can_load": True},
                {"name": "loaded", "is_loaded": True, "can_load": False},
            ]
        }

    async def test_list_datasets_only_reads_memory_and_provider_metadata_async(
        self, *, sqlite_instance: MemoryInterface, registered_provider: MagicMock
    ) -> None:
        sqlite_instance._insert_entries(
            entries=[SeedEntry(entry=SeedObjective(value="Stored", dataset_name="memory-only", added_by="test"))]
        )

        result = await DatasetService().list_datasets_async()

        assert result.model_dump() == {
            "items": [
                {"name": "memory-only", "is_loaded": True, "can_load": False},
                {"name": "test_dataset", "is_loaded": False, "can_load": True},
            ]
        }
        registered_provider.fetch_dataset_async.assert_not_awaited()

    async def test_list_datasets_io_runs_off_event_loop_async(
        self, *, dataset_service: DatasetService, mock_memory: MagicMock, registered_provider: MagicMock
    ) -> None:
        request_thread = get_ident()
        worker_threads: list[int] = []

        def read_names() -> list[str]:
            worker_threads.append(get_ident())
            return []

        async def parse_metadata_async() -> None:
            worker_threads.append(get_ident())

        mock_memory.get_seed_dataset_names.side_effect = read_names
        registered_provider._parse_metadata_async.side_effect = parse_metadata_async

        await dataset_service.list_datasets_async()

        assert len(worker_threads) == 2
        assert all(worker != request_thread for worker in worker_threads)


@pytest.mark.usefixtures("patch_central_database", "registered_provider")
class TestLoadDataset:
    async def test_load_dataset_uses_initializer_and_persists_before_returning_async(
        self, *, sqlite_instance: MemoryInterface, registered_provider: MagicMock
    ) -> None:
        service = DatasetService()
        with patch.object(
            LoadDefaultDatasets,
            "set_params_from_args",
            autospec=True,
            side_effect=LoadDefaultDatasets.set_params_from_args,
        ) as configure:
            result = await service.load_dataset_async(dataset_name="test_dataset")

        assert result.model_dump() == {"name": "test_dataset", "is_loaded": True, "can_load": True}
        assert configure.call_args.kwargs == {"args": {"dataset_names": ["test_dataset"]}}
        stored = sqlite_instance.get_seeds(dataset_name="test_dataset")
        assert len(stored) == 1
        assert stored[0].value == "A loaded objective"
        assert stored[0].added_by == "LoadDefaultDatasets"
        registered_provider.fetch_dataset_async.assert_awaited_once_with(cache=True)
        assert (await service.list_datasets_async()).items == [result]
        assert (await service.list_dataset_seeds_async(dataset_name="test_dataset")).total == 1

    @pytest.mark.parametrize(("name", "can_load"), [("test_dataset", True), ("memory-only", False)])
    async def test_load_dataset_skips_existing_rows_without_fetching_async(
        self, *, sqlite_instance: MemoryInterface, registered_provider: MagicMock, name: str, can_load: bool
    ) -> None:
        seed = SeedObjective(value="Keep this", dataset_name=name, added_by="test")
        sqlite_instance._insert_entries(entries=[SeedEntry(entry=seed)])

        result = await DatasetService().load_dataset_async(dataset_name=name)

        assert result.model_dump() == {"name": name, "is_loaded": True, "can_load": can_load}
        assert [item.id for item in sqlite_instance.get_seeds(dataset_name=name)] == [seed.id]
        registered_provider.fetch_dataset_async.assert_not_awaited()

    @pytest.mark.parametrize("name", ["unknown", " test_dataset ", "TEST_DATASET"])
    async def test_load_dataset_rejects_unknown_exact_name_async(
        self, *, registered_provider: MagicMock, name: str
    ) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            await DatasetService().load_dataset_async(dataset_name=name)
        registered_provider.fetch_dataset_async.assert_not_awaited()

    @pytest.mark.parametrize("name", ["", " \t\n"])
    async def test_load_dataset_rejects_blank_name_async(self, *, registered_provider: MagicMock, name: str) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            await DatasetService().load_dataset_async(dataset_name=name)
        registered_provider._parse_metadata_async.assert_not_awaited()
        registered_provider.fetch_dataset_async.assert_not_awaited()

    async def test_load_dataset_rejects_empty_result_async(self, registered_provider: MagicMock) -> None:
        registered_provider.fetch_dataset_async.return_value = SeedDataset.model_construct(seeds=[])
        service = DatasetService()

        with pytest.raises(DatasetLoadError, match="did not load any seeds"):
            await service.load_dataset_async(dataset_name="test_dataset")

        assert not (await service.list_datasets_async()).items[0].is_loaded

    async def test_load_dataset_does_not_count_other_dataset_rows_async(self, registered_provider: MagicMock) -> None:
        registered_provider.fetch_dataset_async.return_value = SeedDataset(
            seeds=[SeedObjective(value="Different dataset", dataset_name="other")]
        )
        service = DatasetService()

        with pytest.raises(DatasetLoadError, match="did not load any seeds"):
            await service.load_dataset_async(dataset_name="test_dataset")

        states = {item.name: item for item in (await service.list_datasets_async()).items}
        assert not states["test_dataset"].is_loaded

    @pytest.mark.parametrize(
        "error", [RuntimeError("private detail"), ValueError("private detail"), FileNotFoundError()]
    )
    async def test_load_dataset_provider_failure_is_logged_and_retryable_async(
        self, *, registered_provider: MagicMock, caplog: pytest.LogCaptureFixture, error: Exception
    ) -> None:
        registered_provider.fetch_dataset_async.side_effect = [
            error,
            registered_provider.fetch_dataset_async.return_value,
        ]
        service = DatasetService()

        with pytest.raises(DatasetLoadError, match="Failed to load dataset 'test_dataset'") as exc:
            await service.load_dataset_async(dataset_name="test_dataset")

        assert exc.value.__cause__ is error
        assert "private detail" not in str(exc.value)
        assert any(record.exc_info for record in caplog.records)
        assert not (await service.list_datasets_async()).items[0].is_loaded
        assert (await service.load_dataset_async(dataset_name="test_dataset")).is_loaded

    async def test_load_dataset_storage_failure_is_not_success_async(self, sqlite_instance: MemoryInterface) -> None:
        service = DatasetService()
        with patch.object(sqlite_instance, "_insert_entries", side_effect=RuntimeError("cannot persist")):
            with pytest.raises(DatasetLoadError, match="Failed to load dataset"):
                await service.load_dataset_async(dataset_name="test_dataset")

        assert not (await service.list_datasets_async()).items[0].is_loaded

    @pytest.mark.parametrize("cancel_first_request", [False, True])
    async def test_concurrent_loads_wait_for_persistence_and_fetch_once_async(
        self,
        *,
        sqlite_instance: MemoryInterface,
        registered_provider: MagicMock,
        cancel_first_request: bool,
    ) -> None:
        started = Event()
        release = Event()
        request_thread = get_ident()
        insert_entries = sqlite_instance._insert_entries

        def persist(*, entries: list[SeedEntry]) -> None:
            assert get_ident() != request_thread
            started.set()
            assert release.wait(timeout=10)
            insert_entries(entries=entries)

        service = DatasetService()
        with patch.object(sqlite_instance, "_insert_entries", side_effect=persist):
            first = asyncio.create_task(service.load_dataset_async(dataset_name="test_dataset"))
            second = None
            try:
                assert await asyncio.to_thread(started.wait, 5)
                assert not first.done()
                assert not (await service.list_datasets_async()).items[0].is_loaded
                if cancel_first_request:
                    first.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await first
                second = asyncio.create_task(service.load_dataset_async(dataset_name="test_dataset"))
                await asyncio.sleep(0)
                assert not second.done()
            finally:
                release.set()
                results = await asyncio.gather(first, *([second] if second is not None else []), return_exceptions=True)

        assert len(results) == 2
        assert results[-1].is_loaded
        if not cancel_first_request:
            assert results[0] == results[1]
        registered_provider.fetch_dataset_async.assert_awaited_once()
        assert len(sqlite_instance.get_seeds(dataset_name="test_dataset")) == 1


@pytest.mark.usefixtures("patch_central_database")
class TestListDatasetSeeds:
    async def test_list_dataset_seeds_never_accesses_providers_async(
        self, *, dataset_service: DatasetService, mock_memory: MagicMock
    ) -> None:
        with patch("pyrit.backend.services.dataset_service.SeedDatasetProvider") as provider:
            result = await dataset_service.list_dataset_seeds_async(dataset_name="provider-only")

        assert result.model_dump() == {"items": [], "total": 0, "offset": 0, "limit": 25}
        mock_memory.get_seed_entries_page.assert_called_once_with(dataset_name="provider-only", limit=25, offset=0)
        assert provider.mock_calls == []
        mock_memory.get_seed_dataset_names.assert_not_called()
        mock_memory.get_seeds.assert_not_called()

    async def test_list_dataset_seeds_forwards_exact_name_and_paging_async(
        self, *, dataset_service: DatasetService, mock_memory: MagicMock
    ) -> None:
        mock_memory.get_seed_entries_page.return_value = ([], 120)

        result = await dataset_service.list_dataset_seeds_async(dataset_name=" name / %_? ", limit=100, offset=200)

        assert result.model_dump() == {"items": [], "total": 120, "offset": 200, "limit": 100}
        mock_memory.get_seed_entries_page.assert_called_once_with(dataset_name=" name / %_? ", limit=100, offset=200)

    @pytest.mark.parametrize(
        ("dataset_name", "limit", "offset"),
        [("", 25, 0), (" \t", 25, 0), ("loaded", 0, 0), ("loaded", 101, 0), ("loaded", 25, -1)],
    )
    async def test_list_dataset_seeds_rejects_invalid_bounds_async(
        self,
        *,
        dataset_service: DatasetService,
        mock_memory: MagicMock,
        dataset_name: str,
        limit: int,
        offset: int,
    ) -> None:
        with pytest.raises(ValueError):
            await dataset_service.list_dataset_seeds_async(dataset_name=dataset_name, limit=limit, offset=offset)

        mock_memory.get_seed_entries_page.assert_not_called()

    @pytest.mark.parametrize(
        ("metadata", "expected"),
        [(None, None), ({}, None), ({"language": "fr"}, "fr"), ({"language": 12}, None)],
    )
    async def test_list_dataset_seeds_language_metadata_async(
        self,
        *,
        dataset_service: DatasetService,
        mock_memory: MagicMock,
        metadata: dict[str, Any] | None,
        expected: str | None,
    ) -> None:
        entry = SeedEntry(entry=SeedPrompt(value="hello", data_type="text", metadata=metadata))
        mock_memory.get_seed_entries_page.return_value = ([entry], 1)

        result = await dataset_service.list_dataset_seeds_async(dataset_name="loaded")

        assert result.items[0].language == expected

    async def test_list_dataset_seeds_propagates_memory_failure_async(
        self, *, dataset_service: DatasetService, mock_memory: MagicMock
    ) -> None:
        mock_memory.get_seed_entries_page.side_effect = RuntimeError("database unavailable")
        with pytest.raises(RuntimeError, match="database unavailable"):
            await dataset_service.list_dataset_seeds_async(dataset_name="loaded")

    async def test_list_dataset_seeds_round_trips_stored_rows_async(self, sqlite_instance: MemoryInterface) -> None:
        group_id = UUID(int=50)
        prompt = SeedPrompt(
            id=UUID(int=1),
            value="<script>alert('x')</script> {{7 * 7}}",
            data_type="text",
            dataset_name="loaded",
            added_by="test",
            name="Example",
            role="user",
            sequence=3,
            prompt_group_id=group_id,
            metadata={"language": "en"},
        )
        objective = SeedObjective(id=UUID(int=2), value="An objective", dataset_name="loaded", added_by="test")
        media = SeedPrompt(
            id=UUID(int=3),
            value=r"C:\unavailable\image.png",
            data_type="image_path",
            dataset_name="loaded",
            added_by="test",
        )
        media_entry = SeedEntry(entry=media)
        media_entry.sequence = None
        sqlite_instance._insert_entries(entries=[media_entry, SeedEntry(entry=objective), SeedEntry(entry=prompt)])
        service = DatasetService()

        with patch.object(sqlite_instance.results_storage_io, "read_file_async", new_callable=AsyncMock) as read_media:
            first = await service.list_dataset_seeds_async(dataset_name="loaded", limit=2)
            second = await service.list_dataset_seeds_async(dataset_name="loaded", limit=2, offset=2)
            beyond = await service.list_dataset_seeds_async(dataset_name="loaded", limit=2, offset=4)

        assert first.items[0].model_dump() == {
            "id": str(prompt.id),
            "value": prompt.value,
            "data_type": "text",
            "seed_type": "prompt",
            "name": "Example",
            "role": "user",
            "language": "en",
            "group_id": str(group_id),
            "sequence": 3,
        }
        assert first.items[1].model_dump() == {
            "id": str(objective.id),
            "value": objective.value,
            "data_type": "text",
            "seed_type": "objective",
            "name": None,
            "role": None,
            "language": None,
            "group_id": None,
            "sequence": None,
        }
        assert second.items[0].value == media.value
        assert second.items[0].data_type == "image_path"
        assert second.items[0].sequence is None
        assert first.total == second.total == beyond.total == 3
        assert beyond.items == []
        read_media.assert_not_awaited()


@pytest.mark.usefixtures("patch_central_database")
def test_get_dataset_service_is_singleton():
    get_dataset_service.cache_clear()
    with patch("pyrit.backend.services.dataset_service.CentralMemory"):
        assert get_dataset_service() is get_dataset_service()
