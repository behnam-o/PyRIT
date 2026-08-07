# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Domain model for OpenAI target configurations persisted in memory."""

from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class OpenAITargetConfig(BaseModel):
    """A reconstructable OpenAI target configuration with a secret reference."""

    id: str = Field(default_factory=lambda: str(uuid4()), description="Stable unique row id.")
    display_name: str
    endpoint: str
    model_name: str
    auth_mode: Literal["api_key", "identity"] = "api_key"
    api_key_secret_uri: str | None = None

    @field_validator("display_name")
    @classmethod
    def _validate_display_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Display name must not be empty.")
        return value

    @model_validator(mode="after")
    def _validate_secret_storage(self) -> "OpenAITargetConfig":
        if self.auth_mode == "api_key" and not self.api_key_secret_uri:
            raise ValueError("API key authentication requires an api_key_secret_uri.")
        if self.auth_mode == "identity" and self.api_key_secret_uri:
            raise ValueError("Identity authentication must not reference an API key secret.")
        return self
