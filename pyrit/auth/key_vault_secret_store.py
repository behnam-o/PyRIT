# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Azure Key Vault storage for persisted target API keys."""

from urllib.parse import urlparse


class KeyVaultSecretStore:
    """Store and retrieve target API keys using Azure Key Vault."""

    def __init__(self, *, vault_url: str) -> None:
        """
        Initialize the secret store.

        Args:
            vault_url (str): Base URL of the Azure Key Vault.
        """
        self._vault_url = vault_url.rstrip("/")

    async def set_secret_async(self, *, name: str, value: str) -> str:
        """
        Store a secret and return its versioned Key Vault URI.

        Args:
            name (str): Key Vault secret name.
            value (str): Secret value to store.

        Returns:
            str: The versioned URI returned by Azure Key Vault.

        Raises:
            RuntimeError: If Azure Key Vault does not return a secret URI.
        """
        from azure.identity.aio import DefaultAzureCredential
        from azure.keyvault.secrets.aio import SecretClient

        credential = DefaultAzureCredential()
        try:
            async with SecretClient(vault_url=self._vault_url, credential=credential) as client:
                secret = await client.set_secret(name, value)
        finally:
            await credential.close()
        if not secret.id:
            raise RuntimeError(f"Azure Key Vault did not return a URI for secret '{name}'.")
        return secret.id

    @staticmethod
    async def get_secret_async(*, secret_uri: str) -> str:
        """
        Retrieve a secret value from its versioned Key Vault URI.

        Args:
            secret_uri (str): A versioned or unversioned Azure Key Vault secret URI.

        Returns:
            str: The stored secret value.

        Raises:
            ValueError: If the URI is invalid or the secret has no value.
        """
        from azure.identity.aio import DefaultAzureCredential
        from azure.keyvault.secrets.aio import SecretClient

        parsed = urlparse(secret_uri)
        path_parts = [part for part in parsed.path.split("/") if part]
        if parsed.scheme != "https" or not parsed.netloc or len(path_parts) not in (2, 3) or path_parts[0] != "secrets":
            raise ValueError(f"Invalid Azure Key Vault secret URI: '{secret_uri}'.")

        credential = DefaultAzureCredential()
        try:
            async with SecretClient(
                vault_url=f"{parsed.scheme}://{parsed.netloc}", credential=credential
            ) as client:
                secret = await client.get_secret(path_parts[1], version=path_parts[2] if len(path_parts) == 3 else None)
        finally:
            await credential.close()
        if secret.value is None:
            raise ValueError(f"Azure Key Vault secret '{secret_uri}' has no value.")
        return secret.value
