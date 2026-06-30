# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Annotation marker for user-settable seed-dataset constructor parameters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any, get_args, get_origin


@dataclass(frozen=True)
class DatasetParameter:
    """
    Mark a loader constructor parameter as a user-settable dataset parameter.

    Attach inside a parameter's ``Annotated[...]`` metadata to opt it in to
    dataset discovery: ``SeedDatasetProvider`` introspects each loader and
    surfaces only the parameters marked this way (see
    ``SeedDatasetProvider.get_dataset_parameters``).

    Usage::

        category: Annotated[str | None, DatasetParameter()] = None
    """


def is_dataset_parameter(annotation: Any) -> bool:
    """
    Return whether an annotation carries a ``DatasetParameter`` marker.

    Args:
        annotation (Any): The annotation object read from a constructor parameter.

    Returns:
        bool: True when the annotation carries a ``DatasetParameter`` marker.
    """
    if get_origin(annotation) is not Annotated:
        return False
    return any(isinstance(meta, DatasetParameter) for meta in get_args(annotation)[1:])
