# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import logging

import pytest

from pyrit.cli._cli_args import _argparse_validator, merge_config_scenario_args
from pyrit.setup.configuration_loader import ScenarioConfig


def test_argparse_validator_no_params_raises():
    """Validator with zero parameters should raise ValueError."""
    no_param_func = eval("lambda: None")
    with pytest.raises(ValueError, match="must have at least one parameter"):
        _argparse_validator(no_param_func)


def test_argparse_validator_wraps_keyword_only():
    """Validator with keyword-only param should work via positional call."""

    def validate_name(*, name: str) -> str:
        if not name:
            raise ValueError("name is required")
        return name.upper()

    wrapped = _argparse_validator(validate_name)
    assert wrapped("hello") == "HELLO"


class TestParseLoadDatasetArg:
    """Tests for the ``--load-dataset`` name:key=val parser."""

    def test_plain_name_returns_string(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        assert _parse_load_dataset_arg("harmbench") == "harmbench"

    def test_single_param_returns_dict(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        assert _parse_load_dataset_arg("harmbench:category=chemical_biological") == {
            "name": "harmbench",
            "args": {"category": "chemical_biological"},
        }

    def test_multiple_params_semicolon_separated(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        assert _parse_load_dataset_arg("harmbench:category=illegal;source_type=public_url") == {
            "name": "harmbench",
            "args": {"category": "illegal", "source_type": "public_url"},
        }

    def test_comma_separated_value_becomes_list(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        assert _parse_load_dataset_arg("ds:tags=a,b,c") == {
            "name": "ds",
            "args": {"tags": ["a", "b", "c"]},
        }

    def test_missing_name_raises(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        with pytest.raises(ValueError, match="missing name"):
            _parse_load_dataset_arg(":key=val")

    def test_param_without_equals_raises(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        with pytest.raises(ValueError, match="expected key=value"):
            _parse_load_dataset_arg("ds:bad")

    def test_empty_key_raises(self):
        from pyrit.cli._cli_args import _parse_load_dataset_arg

        with pytest.raises(ValueError, match="empty key"):
            _parse_load_dataset_arg("ds:=val")



class TestMergeConfigScenarioArgs:
    """Tests for the shared CLI/shell config-args merge helper."""

    def test_cli_wins_over_matching_config(self):
        """Config args apply when names match; CLI overrides per-key."""
        config = ScenarioConfig(name="scam", args={"max_turns": 5, "mode": "fast"})
        merged = merge_config_scenario_args(
            config_scenario=config,
            effective_scenario_name="scam",
            cli_args={"max_turns": 10},
        )
        assert merged == {"max_turns": 10, "mode": "fast"}

    def test_warns_and_skips_when_scenario_name_differs(self, caplog):
        """A scenario-name mismatch drops config args and emits a warning."""
        config = ScenarioConfig(name="scam", args={"max_turns": 5})
        with caplog.at_level(logging.WARNING):
            merged = merge_config_scenario_args(
                config_scenario=config,
                effective_scenario_name="other_scenario",
                cli_args={},
            )
        assert merged == {}
        assert "scam" in caplog.text
        assert "other_scenario" in caplog.text

    def test_no_warning_when_config_args_empty(self, caplog):
        """An empty/None args block should not produce a warning even on name mismatch."""
        config = ScenarioConfig(name="scam", args=None)
        with caplog.at_level(logging.WARNING):
            merged = merge_config_scenario_args(
                config_scenario=config,
                effective_scenario_name="other_scenario",
                cli_args={"x": 1},
            )
        assert merged == {"x": 1}
        assert caplog.text == ""

    def test_none_config_returns_cli_args(self):
        """When no scenario block is configured, the helper just passes CLI args through."""
        merged = merge_config_scenario_args(
            config_scenario=None,
            effective_scenario_name="scam",
            cli_args={"max_turns": 10},
        )
        assert merged == {"max_turns": 10}
