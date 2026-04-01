# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from abc import ABC
from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar


# TODO: if/when we move to python 3.11+, we can replace this with StrEnum
class _StrEnum(str, Enum):
    """Base class that mimics StrEnum behavior for Python < 3.11."""

    def __str__(self) -> str:
        return str(self.value)


T = TypeVar("T", bound=_StrEnum)


class IdentifierProperty(_StrEnum):
    """Allowed JSON paths for identifier filtering."""

    HASH = "$.hash"
    CLASS_NAME = "$.class_name"


@dataclass(frozen=True)
class IdentifierFilter(ABC, Generic[T]):
    """Immutable filter definition for matching JSON-backed identifier properties."""

    property_path: T | str
    value_to_match: str
    partial_match: bool = False

    def __post_init__(self) -> None:
        """Normalize and validate the configured property path."""
        object.__setattr__(self, "property_path", str(self.property_path))


class AttackIdentifierProperty(_StrEnum):
    """Allowed JSON paths for attack identifier filtering."""

    HASH = "$.hash"
    ATTACK_CLASS_NAME = "$.children.attack.class_name"
    REQUEST_CONVERTERS = "$.children.attack.children.request_converters"


class TargetIdentifierProperty(_StrEnum):
    """Allowed JSON paths for target identifier filtering."""

    HASH = "$.hash"
    ENDPOINT = "$.endpoint"
    MODEL_NAME = "$.model_name"


class ConverterIdentifierProperty(_StrEnum):
    """Allowed JSON paths for converter identifier filtering."""

    HASH = "$.hash"
    CLASS_NAME = "$.class_name"


class ScorerIdentifierProperty(_StrEnum):
    """Allowed JSON paths for scorer identifier filtering."""

    HASH = "$.hash"
    CLASS_NAME = "$.class_name"


@dataclass(frozen=True)
class AttackIdentifierFilter(IdentifierFilter[AttackIdentifierProperty]):
    """
    Immutable filter definition for matching JSON-backed attack identifier properties.

    Args:
        property_path: The JSON path of the property to filter on.
        value_to_match: The value to match against the property.
        partial_match: Whether to allow partial matches (default: False).
    """


@dataclass(frozen=True)
class TargetIdentifierFilter(IdentifierFilter[TargetIdentifierProperty]):
    """Immutable filter definition for matching JSON-backed target identifier properties."""


@dataclass(frozen=True)
class ConverterIdentifierFilter(IdentifierFilter[ConverterIdentifierProperty]):
    """Immutable filter definition for matching JSON-backed converter identifier properties."""


@dataclass(frozen=True)
class ScorerIdentifierFilter(IdentifierFilter[ScorerIdentifierProperty]):
    """Immutable filter definition for matching JSON-backed scorer identifier properties."""
