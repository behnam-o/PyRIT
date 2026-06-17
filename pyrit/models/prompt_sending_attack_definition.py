# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from pyrit.models.target_definition import TargetDefinition


class Base64EncodingFunction(str, Enum):
    b64encode = "b64encode"
    urlsafe_b64encode = "urlsafe_b64encode"
    standard_b64encode = "standard_b64encode"
    b2a_base64 = "b2a_base64"
    b16encode = "b16encode"
    b32encode = "b32encode"
    a85encode = "a85encode"
    b85encode = "b85encode"


class Base64ConverterDefinition(BaseModel):
    """Durable configuration descriptor for a Base64 converter."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    encoding_func: Base64EncodingFunction = Base64EncodingFunction.b64encode


class PromptSendingAttackDefinition(BaseModel):
    """Durable configuration descriptor for ``PromptSendingAttack``."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    target_definition: TargetDefinition
    converter_definitions: list[Base64ConverterDefinition] = Field(default_factory=list)
