# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Domain model for OpenAI target configurations persisted in memory."""

from typing import Literal

from pydantic import BaseModel, model_validator


class OpenAITargetConfig(BaseModel):
    """A reconstructable OpenAI target configuration with a secret reference."""

    target_registry_name: str
    endpoint: str
    model_name: str
    auth_mode: Literal["api_key", "identity"] = "api_key"
    api_key_secret_uri: str | None = None

    @model_validator(mode="after")
    def _validate_secret_storage(self) -> "OpenAITargetConfig":
        if self.auth_mode == "api_key" and not self.api_key_secret_uri:
            raise ValueError("API key authentication requires an api_key_secret_uri.")
        if self.auth_mode == "identity" and self.api_key_secret_uri:
            raise ValueError("Identity authentication must not reference an API key secret.")
        return self
