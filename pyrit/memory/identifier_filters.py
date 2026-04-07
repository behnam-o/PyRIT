# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from dataclasses import dataclass

from prometheus_client import Enum


class IdentifierType(Enum):
    """Enumeration of supported identifier types for filtering."""

    ATTACK = "attack"
    TARGET = "target"
    SCORER = "scorer"
    CONVERTER = "converter"


@dataclass(frozen=True)
class IdentifierFilter:
    """Immutable filter definition for matching JSON-backed identifier properties."""

    identifier_type: IdentifierType
    property_path: str
    sub_path: str | None
    value_to_match: str
    partial_match: bool = False

    def __post_init__(self) -> None:
        """
        Validate that the filter configuration.

        Raises:
            ValueError: If the filter configuration is not valid.
        """
        if self.partial_match and self.sub_path:
            raise ValueError("Cannot use sub_path with partial_match")
