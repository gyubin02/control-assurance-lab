"""Concrete key-management boundaries used by production adapters."""

from assurance_lab.key_management.azure_key_vault import (
    AZURE_KEY_VAULT_SCOPE,
    AzureKeyVaultBearerToken,
    AzureKeyVaultCryptoClient,
    AzureKeyVaultEnvelopeProtector,
    AzureKeyVaultError,
    AzureKeyVaultPS256Signer,
    AzureKeyVaultTokenProvider,
)
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretClient,
    AzureKeyVaultSecretError,
    AzureKeyVaultSecretReference,
    AzureKeyVaultSecretValue,
)

__all__ = [
    "AZURE_KEY_VAULT_SCOPE",
    "AzureKeyVaultBearerToken",
    "AzureKeyVaultCryptoClient",
    "AzureKeyVaultEnvelopeProtector",
    "AzureKeyVaultError",
    "AzureKeyVaultPS256Signer",
    "AzureKeyVaultSecretClient",
    "AzureKeyVaultSecretError",
    "AzureKeyVaultSecretReference",
    "AzureKeyVaultSecretValue",
    "AzureKeyVaultTokenProvider",
]
