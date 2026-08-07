# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Target API routes.

Provides endpoints for managing target instances.
Target types are set at app startup via initializers - you cannot add new types at runtime.
"""

from fastapi import APIRouter, HTTPException, Query, status

from pyrit.backend.models.common import ProblemDetail
from pyrit.backend.models.targets import (
    CreatePersistedTargetRequest,
    CreateTargetRequest,
    PersistedTargetListResponse,
    TargetCatalogResponse,
    TargetListResponse,
)
from pyrit.backend.services.target_service import get_target_service
from pyrit.models import OpenAITargetConfig
from pyrit.models.catalog.target import TargetInstance

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get(
    "",
    response_model=TargetListResponse,
    responses={
        500: {"model": ProblemDetail, "description": "Internal server error"},
    },
)
async def list_targets(  # pyrit-async-suffix-exempt
    limit: int = Query(50, ge=1, le=200, description="Maximum items per page"),
    cursor: str | None = Query(None, description="Pagination cursor (target_registry_name)"),
) -> TargetListResponse:
    """
    List target instances with pagination.

    Returns paginated target instances.

    Returns:
        TargetListResponse: Paginated list of target instances.
    """
    service = get_target_service()
    return await service.list_targets_async(limit=limit, cursor=cursor)


@router.get(
    "/catalog",
    response_model=TargetCatalogResponse,
    responses={
        500: {"model": ProblemDetail, "description": "Internal server error"},
    },
)
async def list_target_catalog() -> TargetCatalogResponse:  # pyrit-async-suffix-exempt
    """
    List all available target types from the backend target registry.

    Returns:
        TargetCatalogResponse: List of available target types.
    """
    service = get_target_service()
    return await service.list_target_catalog_async()


@router.get("/persisted", response_model=PersistedTargetListResponse)
async def list_persisted_targets() -> PersistedTargetListResponse:  # pyrit-async-suffix-exempt
    """
    List persisted OpenAI Responses target configurations.

    Returns:
        PersistedTargetListResponse: The stored target configurations.
    """
    return await get_target_service().list_persisted_targets_async()


@router.post("/persisted", response_model=OpenAITargetConfig, status_code=status.HTTP_201_CREATED)
async def create_persisted_target(  # pyrit-async-suffix-exempt
    request: CreatePersistedTargetRequest,
) -> OpenAITargetConfig:
    """
    Create a persisted OpenAI Responses target configuration.

    Returns:
        OpenAITargetConfig: The newly stored target configuration.
    """
    try:
        return await get_target_service().create_persisted_target_async(request=request)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist target: {str(e)}",
        ) from e


@router.delete("/persisted/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_persisted_target(target_id: str) -> None:  # pyrit-async-suffix-exempt
    """Delete a persisted target configuration."""
    await get_target_service().delete_persisted_target_async(target_id=target_id)


@router.post(
    "",
    response_model=TargetInstance,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {
            "model": ProblemDetail,
            "description": "Invalid target type or parameters",
        },
    },
)
async def create_target(
    request: CreateTargetRequest,
) -> TargetInstance:  # pyrit-async-suffix-exempt
    """
    Create a new target instance.

    Instantiates a target with the given type and parameters.
    The target becomes available for use in attacks.

    Note: Sensitive parameters (API keys, tokens) are filtered from the response.

    Returns:
        CreateTargetResponse: The created target instance details.
    """
    service = get_target_service()

    try:
        return await service.create_target_async(request=request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create target: {str(e)}",
        ) from e


@router.get(
    "/{target_registry_name}",
    response_model=TargetInstance,
    responses={
        404: {"model": ProblemDetail, "description": "Target not found"},
    },
)
async def get_target(
    target_registry_name: str,
) -> TargetInstance:  # pyrit-async-suffix-exempt
    """
    Get a target instance by registry name.

    Returns:
        TargetInstance: The target instance details.
    """
    service = get_target_service()

    target = await service.get_target_async(target_registry_name=target_registry_name)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target '{target_registry_name}' not found",
        )

    return target
