# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Dataset service for listing and loading seed datasets.

Wraps ``SeedDatasetProvider`` discovery/fetching and ``CentralMemory`` so the
API can list available datasets and load them into memory. Mirrors the behavior
of the ``LoadDefaultDatasets`` initializer.
"""

import logging
from functools import lru_cache

from pyrit.backend.models.datasets import (
    DatasetInfo,
    DatasetListResponse,
    DatasetParameterInfo,
    LoadDatasetRequest,
    LoadDatasetResponse,
    LoadedDataset,
)
from pyrit.common.apply_defaults import REQUIRED_VALUE
from pyrit.datasets import SeedDatasetProvider
from pyrit.memory import CentralMemory
from pyrit.models.parameter import Parameter
from pyrit.registry.resolution import display_choices

logger = logging.getLogger(__name__)

_ADDED_BY = "DatasetService"


class DatasetService:
    """Service for listing and loading seed datasets."""

    async def list_datasets_async(self) -> DatasetListResponse:
        """
        List all available datasets and whether they are already in memory.

        Returns:
            DatasetListResponse: Available datasets with their loaded status and parameters.
        """
        memory = CentralMemory.get_memory_instance()
        loaded = set(memory.get_seed_dataset_names())

        items: list[DatasetInfo] = []
        for class_name, provider_class in SeedDatasetProvider.get_all_providers().items():
            name = provider_class().dataset_name
            parameters = SeedDatasetProvider.get_dataset_parameters(class_name=class_name)
            items.append(
                DatasetInfo(
                    name=name,
                    loaded=name in loaded,
                    parameters=[self._to_parameter_info(param=param) for param in parameters],
                )
            )

        items.sort(key=lambda item: item.name)
        return DatasetListResponse(items=items)

    @staticmethod
    def _to_parameter_info(*, param: Parameter) -> DatasetParameterInfo:
        """
        Project a derived ``Parameter`` into its serializable API model.

        Args:
            param (Parameter): The introspected loader parameter.

        Returns:
            DatasetParameterInfo: The wire representation of the parameter.
        """
        required = param.default is REQUIRED_VALUE
        choices = display_choices(param.param_type)
        return DatasetParameterInfo(
            name=param.name,
            description=param.description,
            required=required,
            default=None if required else param.default,
            choices=list(choices) if choices is not None else None,
        )

    async def load_datasets_async(self, *, request: LoadDatasetRequest) -> LoadDatasetResponse:
        """
        Fetch the requested datasets and add their seeds to memory.

        Args:
            request: The dataset names to load and whether to cache them.

        Returns:
            LoadDatasetResponse: Summary of the datasets loaded and total seed count.

        Raises:
            ValueError: If any requested dataset name does not exist.
        """
        datasets = await SeedDatasetProvider.fetch_datasets_async(
            dataset_names=request.dataset_names,
            dataset_parameters=request.dataset_parameters,
            cache=request.cache,
        )

        memory = CentralMemory.get_memory_instance()
        await memory.add_seed_datasets_to_memory_async(datasets=datasets, added_by=_ADDED_BY)

        loaded_datasets = [
            LoadedDataset(name=dataset.dataset_name or "unknown", seed_count=len(dataset.seeds)) for dataset in datasets
        ]
        total_seeds = sum(item.seed_count for item in loaded_datasets)

        logger.info(f"Loaded {len(loaded_datasets)} datasets ({total_seeds} seeds) into memory")
        return LoadDatasetResponse(loaded_datasets=loaded_datasets, total_seeds=total_seeds)


@lru_cache(maxsize=1)
def get_dataset_service() -> DatasetService:
    """
    Get the global dataset service instance.

    Returns:
        The singleton DatasetService instance.
    """
    return DatasetService()
