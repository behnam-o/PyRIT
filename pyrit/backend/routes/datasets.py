# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Dataset API routes.

Lists available datasets, explicitly loads them, and browses stored seeds.
"""

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import JSONResponse

from pyrit.backend.models.common import ProblemDetail
from pyrit.backend.models.datasets import (
    DatasetInfo,
    DatasetListResponse,
    DatasetLoadRequest,
    DatasetSeedListResponse,
)
from pyrit.backend.services.dataset_service import DatasetLoadError, get_dataset_service

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.get(
    "",
    response_model=DatasetListResponse,
    responses={
        500: {"model": ProblemDetail, "description": "Internal server error"},
    },
)
async def list_datasets() -> DatasetListResponse:  # pyrit-async-suffix-exempt
    """
    List all available datasets.

    Returns:
        DatasetListResponse: Available datasets.
    """
    service = get_dataset_service()
    return await service.list_datasets_async()


@router.post(
    "/load",
    response_model=DatasetInfo,
    responses={
        404: {"model": ProblemDetail, "description": "Dataset not found"},
        422: {"model": ProblemDetail, "description": "Invalid dataset name"},
        500: {"model": ProblemDetail, "description": "Dataset load failed"},
    },
)
async def load_dataset_async(*, body: DatasetLoadRequest, request: Request) -> DatasetInfo | JSONResponse:
    """
    Load a dataset through its registered provider, without reloading existing rows.

    Args:
        body (DatasetLoadRequest): Exact dataset name to load.
        request (Request): HTTP request used to identify error responses.

    Returns:
        DatasetInfo | JSONResponse: Verified state or a dataset load problem detail.
    """
    service = get_dataset_service()
    try:
        return await service.load_dataset_async(dataset_name=body.dataset_name)
    except DatasetLoadError as exc:
        problem = ProblemDetail(
            type="/errors/dataset-load-failed",
            title="Dataset Load Failed",
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
            instance=request.url.path,
        )
        return JSONResponse(status_code=problem.status, content=problem.model_dump(exclude_none=True))


@router.get(
    "/seeds",
    response_model=DatasetSeedListResponse,
    responses={
        500: {"model": ProblemDetail, "description": "Internal server error"},
    },
)
async def list_dataset_seeds_async(
    *,
    dataset_name: str = Query(..., min_length=1, pattern=r"\S", description="Exact dataset name"),
    limit: int = Query(25, ge=1, le=100, description="Maximum seeds per page"),
    offset: int = Query(0, ge=0, description="Number of seeds to skip"),
) -> DatasetSeedListResponse:
    """
    List loaded seeds without fetching providers or resolving media values.

    Args:
        dataset_name (str): Exact name of the dataset in memory.
        limit (int): Maximum seeds per page.
        offset (int): Number of seeds to skip.

    Returns:
        DatasetSeedListResponse: A page of loaded seeds and the matching total.
    """
    service = get_dataset_service()
    return await service.list_dataset_seeds_async(dataset_name=dataset_name, limit=limit, offset=offset)
