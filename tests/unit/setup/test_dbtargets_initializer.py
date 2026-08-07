# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from unittest.mock import AsyncMock, patch

from pyrit.models import OpenAITargetConfig
from pyrit.prompt_target import OpenAIResponseTarget
from pyrit.registry import TargetRegistry
from pyrit.setup.initializers.dbtargets import DbtargetsInitializer


async def test_initialize_registers_api_key_target(sqlite_instance) -> None:
    sqlite_instance.add_openai_target_config(
        target=OpenAITargetConfig(
            target_registry_name="saved-target",
            endpoint="https://example.test",
            model_name="model",
            api_key_secret_uri="https://vault.vault.azure.net/secrets/key/version",
        )
    )

    with patch(
        "pyrit.setup.initializers.dbtargets.KeyVaultSecretStore.get_secret_async",
        new_callable=AsyncMock,
        return_value="secret-value",
    ) as get_secret:
        await DbtargetsInitializer().initialize_async()

    target = TargetRegistry.get_registry_singleton().instances.get("saved-target")
    assert isinstance(target, OpenAIResponseTarget)
    assert target._api_key == "secret-value"
    get_secret.assert_awaited_once()


async def test_initialize_registers_identity_target(sqlite_instance) -> None:
    sqlite_instance.add_openai_target_config(
        target=OpenAITargetConfig(
            target_registry_name="identity-target",
            endpoint="https://example.openai.azure.com",
            model_name="model",
            auth_mode="identity",
        )
    )

    token_provider = AsyncMock(return_value="token")
    with patch(
        "pyrit.prompt_target.openai.openai_target.get_azure_openai_auth",
        return_value=token_provider,
    ):
        await DbtargetsInitializer().initialize_async()

    target = TargetRegistry.get_registry_singleton().instances.get("identity-target")
    assert isinstance(target, OpenAIResponseTarget)
