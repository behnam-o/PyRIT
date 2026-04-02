# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from dataclasses import dataclass


@dataclass(frozen=True)
class IdentifierFilter:
    """Immutable filter definition for matching JSON-backed identifier properties."""

    property_path: str
    value_to_match: str
    partial_match: bool = False
