# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from pydantic import ValidationError

from pyrit.models import OpenAITargetConfig


def test_api_key_auth_requires_secret_uri() -> None:
    with pytest.raises(ValidationError, match="api_key_secret_uri"):
        OpenAITargetConfig(
            display_name="Target",
            endpoint="https://example.test",
            model_name="model",
            auth_mode="api_key",
        )


def test_identity_auth_rejects_secret_uri() -> None:
    with pytest.raises(ValidationError, match="must not reference"):
        OpenAITargetConfig(
            display_name="Target",
            endpoint="https://example.test",
            model_name="model",
            auth_mode="identity",
            api_key_secret_uri="https://vault.vault.azure.net/secrets/key/version",
        )
