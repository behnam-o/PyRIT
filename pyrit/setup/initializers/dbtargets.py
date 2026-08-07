# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Initializer for targets persisted in the PyRIT database."""

import asyncio

from pyrit.auth.key_vault_secret_store import KeyVaultSecretStore
from pyrit.memory import CentralMemory
from pyrit.prompt_target import OpenAIResponseTarget
from pyrit.registry import TargetRegistry
from pyrit.setup.pyrit_initializer import PyRITInitializer


class DbtargetsInitializer(PyRITInitializer):
    """Load database-backed OpenAI Responses targets into the target registry."""

    async def initialize_async(self) -> None:
        """Load persisted target configurations and register their target instances."""
        memory = CentralMemory.get_memory_instance()
        targets = await asyncio.to_thread(memory.get_openai_target_configs)
        registry = TargetRegistry.get_registry_singleton()

        for target in targets:
            api_key = None
            if target.api_key_secret_uri:
                api_key = await KeyVaultSecretStore.get_secret_async(secret_uri=target.api_key_secret_uri)

            target_instance = OpenAIResponseTarget(
                endpoint=target.endpoint,
                model_name=target.model_name,
                api_key=api_key,
            )
            registry.instances.register(target_instance)
