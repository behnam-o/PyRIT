# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Custom constructor input resolution for built-in word selection."""

import re
from typing import Any, get_args

from pydantic import TypeAdapter, ValidationError

from pyrit.converter.text_selection_strategy import (
    AllWordsSelectionStrategy,
    ContentWordSelectionStrategy,
    WordIndexSelectionStrategy,
    WordKeywordSelectionStrategy,
    WordPositionSelectionStrategy,
    WordProportionSelectionStrategy,
    WordRegexSelectionStrategy,
    WordSelectionStrategy,
)
from pyrit.models import Parameter

_STRATEGIES: dict[str, type[WordSelectionStrategy]] = {
    "all": AllWordsSelectionStrategy,
    "random": WordProportionSelectionStrategy,
    "position": WordPositionSelectionStrategy,
    "indices": WordIndexSelectionStrategy,
    "keywords": WordKeywordSelectionStrategy,
    "regex": WordRegexSelectionStrategy,
    "content": ContentWordSelectionStrategy,
}


def word_selection_parameters(annotation: Any) -> dict[str, list[Parameter]] | None:
    """
    Project the built-in strategy constructors onto their JSON inputs.

    Returns:
        dict[str, list[Parameter]] | None: Typed fields by strategy, or None for other annotations.
    """
    if annotation is not WordSelectionStrategy:
        return None

    from pyrit.registry.resolution import derive_parameters

    result: dict[str, list[Parameter]] = {}
    for name, strategy in _STRATEGIES.items():
        parameters = derive_parameters(cls=strategy)
        # Python also accepts compiled patterns and collections; JSON uses strings and arrays.
        wire_types = {"pattern": str, "stopwords": list[str] | None, "candidate_words": list[str] | None}
        result[name] = [
            param.model_copy(update={"param_type": wire_types[param.name]}) if param.name in wire_types else param
            for param in parameters
        ]
    return result


def resolve_word_selection(*, parameter: Parameter, value: Any) -> WordSelectionStrategy | None:
    """
    Build a known strategy, or preserve an existing Python strategy by identity.

    Returns:
        WordSelectionStrategy | None: The selected strategy, or the allowed default sentinel.

    Raises:
        ValueError: If the strategy type, fields, or typed values are invalid.
    """
    if isinstance(value, WordSelectionStrategy):
        return value
    if value is None and type(None) in get_args(parameter.param_type):
        return None
    try:
        if not isinstance(value, dict) or set(value) - {"type", "parameters"}:
            raise ValueError("expected an object with 'type' and optional 'parameters'")
        name = value.get("type")
        if not isinstance(name, str) or name not in _STRATEGIES:
            raise ValueError(f"type must be one of {list(_STRATEGIES)}")
        supplied = value.get("parameters", {})
        if not isinstance(supplied, dict):
            raise ValueError("parameters must be an object")
        assert parameter.word_selection is not None
        declared = {param.name: param for param in parameter.word_selection[name]}
        unknown = supplied.keys() - declared.keys()
        if unknown:
            raise ValueError(f"unknown parameters for '{name}': {sorted(unknown)}")
        missing = [param.name for param in declared.values() if param.required and param.name not in supplied]
        if missing:
            raise ValueError(f"missing parameters for '{name}': {missing}")
        args = {key: _coerce_selection_input(parameter=declared[key], value=raw) for key, raw in supplied.items()}
        return _STRATEGIES[name](**args)
    except (ValueError, re.error) as exc:
        raise ValueError(f"Parameter '{parameter.name}': {exc}") from exc


def _coerce_selection_input(*, parameter: Parameter, value: Any) -> Any:
    """
    Check the JSON shape before the shared coercer can perform a lossy cast.

    Returns:
        Any: The value coerced by the nested parameter.

    Raises:
        ValueError: If the input does not match the declared JSON type.
    """
    try:
        TypeAdapter(parameter.param_type).validate_python(value, strict=True)
    except ValidationError as exc:
        raise ValueError(f"'{parameter.name}' expects {parameter.type_name}: {exc}") from exc
    return parameter.coerce_value(value)
