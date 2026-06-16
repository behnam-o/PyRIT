# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from pyrit.models.identifiers import validate_registry_name


class TargetType(str, Enum):
    azure_ml_chat = "azure_ml_chat"
    openai_chat = "openai_chat"
    openai_completion = "openai_completion"
    openai_image = "openai_image"
    openai_response = "openai_response"
    openai_tts = "openai_tts"
    openai_video = "openai_video"
    prompt_shield = "prompt_shield"
    realtime = "realtime"


class AuthMode(str, Enum):
    api_key = "api_key"
    azure_ad = "azure_ad"
    unauthenticated = "unauthenticated"


class TargetDefinition(BaseModel):
    """
    Durable configuration descriptor for a prompt target.

    This model describes a target definition that can be persisted and later
    translated into a live ``PromptTarget`` instance by runtime code. It is
    intentionally narrower than the runtime target object and excludes secrets,
    clients, caches, and other non-durable state.
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    target_type: TargetType
    endpoint: str
    model_name: str | None = None
    underlying_model: str | None = None
    temperature: float | None = None
    extra_kwargs: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    is_enabled: bool = True
    is_default_objective_target: bool = False
    auth_mode: AuthMode = AuthMode.api_key
    api_key_env_var: str | None = None

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        validate_registry_name(value)
        return value
