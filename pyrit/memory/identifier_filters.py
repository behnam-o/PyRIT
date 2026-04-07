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
    """
    Immutable filter definition for matching JSON-backed identifier properties.

    Attributes:
        identifier_type: The type of identifier column to filter on.
        property_path: The JSON path for the property to match.
        sub_path: An optional JSON path that indicates the property at property_path is an array
            and the condition should resolve if any element in that array matches the value.
            Cannot be used with partial_match.
        value_to_match: The string value that must match the extracted JSON property value.
        partial_match: Whether to perform a substring match. Cannot be used with sub_path.
        case_sensitive: Whether the match should be case-sensitive. Defaults to False.
    """

    identifier_type: IdentifierType
    property_path: str
    sub_path: str | None
    value_to_match: str
    partial_match: bool = False
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        """
        Validate the filter configuration.

        Raises:
            ValueError: If the filter configuration is not valid.
        """
        if self.sub_path and (self.partial_match or self.case_sensitive):
            raise ValueError("Cannot use sub_path with partial_match or case_sensitive")
