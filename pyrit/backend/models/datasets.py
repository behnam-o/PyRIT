# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Dataset models for the PyRIT API.

These models describe available datasets, explicit load requests, and read-only
pages of seeds already loaded into memory.
"""

from pydantic import BaseModel, Field


class DatasetInfo(BaseModel):
    """Metadata about a single available dataset."""

    name: str = Field(..., description="Dataset name (e.g., 'harmbench')")
    is_loaded: bool = Field(..., description="Whether this dataset has seed rows in memory")
    can_load: bool = Field(..., description="Whether this dataset has a registered provider")


class DatasetLoadRequest(BaseModel):
    """Request to load an exact dataset name without reloading existing seeds."""

    dataset_name: str = Field(..., min_length=1, pattern=r"\S", description="Exact registered dataset name")


class DatasetListResponse(BaseModel):
    """Response for listing available datasets."""

    items: list[DatasetInfo] = Field(..., description="List of available datasets")


class DatasetSeedInfo(BaseModel):
    """Stored seed content and metadata, without resolving media values."""

    id: str
    value: str
    data_type: str
    seed_type: str
    name: str | None = None
    role: str | None = None
    language: str | None = Field(None, description="String language metadata, when present")
    group_id: str | None = None
    sequence: int | None = None


class DatasetSeedListResponse(BaseModel):
    """A bounded page of loaded seeds for an exact dataset name."""

    items: list[DatasetSeedInfo]
    total: int = Field(..., ge=0)
    offset: int = Field(..., ge=0)
    limit: int = Field(..., ge=1, le=100)
