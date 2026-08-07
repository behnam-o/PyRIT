# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from pyrit.models import OpenAITargetConfig


def test_openai_target_config_round_trip(sqlite_instance) -> None:
    config = OpenAITargetConfig(
        display_name="Saved target",
        endpoint="https://example.test",
        model_name="model",
        auth_mode="identity",
    )

    sqlite_instance.add_openai_target_config(target=config)

    assert sqlite_instance.get_openai_target_configs() == [config]


def test_delete_openai_target_config(sqlite_instance) -> None:
    config = OpenAITargetConfig(
        display_name="Saved target",
        endpoint="https://example.test",
        model_name="model",
        auth_mode="identity",
    )
    sqlite_instance.add_openai_target_config(target=config)

    sqlite_instance.delete_openai_target_config(target_id=config.id)

    assert sqlite_instance.get_openai_target_configs() == []
