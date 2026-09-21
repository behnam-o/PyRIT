# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Dataset service for listing, loading, and browsing datasets.

Wraps ``SeedDatasetProvider`` discovery and memory to list available datasets.
"""

import asyncio
import logging
from functools import lru_cache
from threading import Lock
from typing import TYPE_CHECKING

from pyrit.backend.models.datasets import (
    DatasetInfo,
    DatasetListResponse,
    DatasetSeedInfo,
    DatasetSeedListResponse,
)
from pyrit.datasets import SeedDatasetProvider
from pyrit.memory import CentralMemory
from pyrit.setup.initializers.load_default_datasets import LoadDefaultDatasets

if TYPE_CHECKING:
    from pyrit.memory.memory_models import SeedEntry

logger = logging.getLogger(__name__)


class DatasetLoadError(RuntimeError):
    """A dataset load failed or did not persist any seeds."""


class DatasetService:
    """Service for listing datasets, explicitly loading them, and reading stored seeds."""

    def __init__(self) -> None:
        """Initialize the dataset service."""
        self._memory = CentralMemory.get_memory_instance()
        self._load_lock = Lock()

    async def list_datasets_async(self) -> DatasetListResponse:
        """
        List all available datasets.

        Combines datasets discoverable via registered providers with those
        already loaded into memory, since both are available for use.

        Returns:
            DatasetListResponse: Available datasets.
        """
        return await asyncio.to_thread(self._list_datasets)

    async def load_dataset_async(self, *, dataset_name: str) -> DatasetInfo:
        """
        Load an explicitly selected dataset, leaving existing seed rows untouched.

        Args:
            dataset_name (str): Exact dataset name.

        Returns:
            DatasetInfo: Dataset state verified against persisted seeds.

        Raises:
            ValueError: If the name is empty or whitespace only.
            FileNotFoundError: If neither memory nor a provider knows the name.
            DatasetLoadError: If loading fails or does not persist any seeds.
        """
        if not dataset_name.strip():
            raise ValueError("dataset_name must not be empty")
        return await asyncio.to_thread(self._load_dataset, dataset_name)

    async def list_dataset_seeds_async(
        self, *, dataset_name: str, limit: int = 25, offset: int = 0
    ) -> DatasetSeedListResponse:
        """
        Read a bounded page of seeds already loaded for an exact dataset name.

        Args:
            dataset_name (str): Exact dataset name; never used to fetch a provider.
            limit (int): Maximum seeds to return, between 1 and 100.
            offset (int): Non-negative number of seeds to skip.

        Returns:
            DatasetSeedListResponse: Stored seeds ordered by ID and the matching total.

        Raises:
            ValueError: If the dataset name or pagination bounds are invalid.
        """
        if not dataset_name.strip():
            raise ValueError("dataset_name must not be empty")
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("limit must be between 1 and 100 and offset must be non-negative")
        entries, total = await asyncio.to_thread(
            self._memory.get_seed_entries_page, dataset_name=dataset_name, limit=limit, offset=offset
        )
        return DatasetSeedListResponse(
            items=[self._to_seed_info(entry) for entry in entries], total=total, offset=offset, limit=limit
        )

    def _list_datasets(self) -> DatasetListResponse:
        """
        Discover providers and inspect memory off the request event loop.

        Returns:
            DatasetListResponse: Provider and memory dataset names with their current state.
        """
        provider_names = set(asyncio.run(SeedDatasetProvider.get_all_dataset_names_async()))
        memory_names = set(self._memory.get_seed_dataset_names())
        return DatasetListResponse(
            items=[
                DatasetInfo(name=name, is_loaded=name in memory_names, can_load=name in provider_names)
                for name in sorted(provider_names | memory_names)
            ]
        )

    def _load_dataset(self, dataset_name: str) -> DatasetInfo:
        """
        Serialize loads, including requests whose callers disconnect before completion.

        Args:
            dataset_name (str): Exact dataset name.

        Returns:
            DatasetInfo: State after checking or loading persisted seeds.

        Raises:
            FileNotFoundError: If the dataset is unknown.
            DatasetLoadError: If loading fails or does not persist any seeds.
        """
        # Provider construction and memory ingestion include synchronous I/O.
        with self._load_lock:
            datasets = self._list_datasets()
            dataset = next((item for item in datasets.items if item.name == dataset_name), None)
            if dataset is None:
                raise FileNotFoundError(f"Dataset '{dataset_name}' not found")
            if dataset.is_loaded:
                return dataset

            initializer = LoadDefaultDatasets()
            initializer.set_params_from_args(args={"dataset_names": [dataset_name]})
            try:
                asyncio.run(initializer.initialize_async())
                dataset.is_loaded = dataset_name in self._memory.get_seed_dataset_names()
            except Exception as exc:
                logger.exception("Failed to load dataset '%s'", dataset_name)
                raise DatasetLoadError(
                    f"Failed to load dataset '{dataset_name}'. See server logs for details."
                ) from exc
            if not dataset.is_loaded:
                logger.error("Dataset '%s' did not load any seeds into memory", dataset_name)
                raise DatasetLoadError(f"Dataset '{dataset_name}' did not load any seeds into memory.")
            return dataset

    @staticmethod
    def _to_seed_info(entry: "SeedEntry") -> DatasetSeedInfo:
        """
        Map stored fields without interpreting seed values or reading media.

        Args:
            entry (SeedEntry): A persisted seed row.

        Returns:
            DatasetSeedInfo: Plain stored content and optional metadata.
        """
        language = (entry.prompt_metadata or {}).get("language")
        return DatasetSeedInfo(
            id=str(entry.id),
            value=entry.value,
            data_type=entry.data_type,
            seed_type=entry.seed_type,
            name=entry.name,
            role=entry.role,
            language=language if isinstance(language, str) else None,
            group_id=str(entry.prompt_group_id) if entry.prompt_group_id is not None else None,
            sequence=entry.sequence,
        )


@lru_cache(maxsize=1)
def get_dataset_service() -> DatasetService:
    """
    Get the global dataset service instance.

    Returns:
        The singleton DatasetService instance.
    """
    return DatasetService()
