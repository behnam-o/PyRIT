# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest

from pyrit.memory import MemoryInterface
from pyrit.memory.identifier_filters import IdentifierFilter, IdentifierType
from pyrit.memory.memory_models import AttackResultEntry


@pytest.mark.parametrize(
    "sub_path, partial_match, case_sensitive",
    [
        ("$.class_name", True, False),
        ("$.class_name", False, True),
        ("$.class_name", True, True),
    ],
    ids=["sub_path+partial_match", "sub_path+case_sensitive", "sub_path+both"],
)
def test_identifier_filter_sub_path_with_partial_or_case_sensitive_raises(
    sub_path: str, partial_match: bool, case_sensitive: bool
):
    with pytest.raises(ValueError, match="Cannot use sub_path with partial_match or case_sensitive"):
        IdentifierFilter(
            identifier_type=IdentifierType.ATTACK,
            property_path="$.children",
            value_to_match="test",
            sub_path=sub_path,
            partial_match=partial_match,
            case_sensitive=case_sensitive,
        )


def test_identifier_filter_valid_with_sub_path():
    f = IdentifierFilter(
        identifier_type=IdentifierType.CONVERTER,
        property_path="$",
        value_to_match="Base64Converter",
        sub_path="$.class_name",
    )
    assert f.sub_path == "$.class_name"
    assert not f.partial_match
    assert not f.case_sensitive


def test_build_identifier_filter_conditions_unsupported_type_raises(sqlite_instance: MemoryInterface):
    filters = {
        IdentifierFilter(
            identifier_type=IdentifierType.SCORER,
            property_path="$.class_name",
            value_to_match="MyScorer",
        )
    }
    with pytest.raises(ValueError, match="does not support identifier type"):
        sqlite_instance._build_identifier_filter_conditions(
            identifier_filters=filters,
            identifier_column_map={IdentifierType.ATTACK: AttackResultEntry.atomic_attack_identifier},
            caller="test_caller",
        )
