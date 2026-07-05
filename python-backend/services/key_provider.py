# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Pluggable Key Provider — Secrets Management Abstraction
────────────────────────────────────────────────────────
Provides a standard interface for loading cryptographic keys from
various sources, enabling HSM/KMS integration without changing
the rest of the codebase.

Built-in providers:
  - EnvironmentKeyProvider: loads PEM keys from env vars or file paths
  - VaultKeyProvider:       loads keys from HashiCorp Vault (placeholder)

Usage:
    provider = EnvironmentKeyProvider(
        env_var="AUTH_PRIVATE_KEY",
        path_var="AUTH_PRIVATE_KEY_PATH",
    )
    pem_bytes = provider.get_private_key()
"""

from __future__ import annotations
import os
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("key_provider")


class KeyNotFoundError(Exception):
    """Raised when a key cannot be loaded from any configured source."""


class BaseKeyProvider(ABC):
    """Abstract base for all key providers."""

    def __init__(self, key_id: Optional[str] = None):
        self.key_id = key_id

    @abstractmethod
    def get_private_key(self) -> bytes:
        """Return the PEM-encoded private key bytes."""
        ...

    @abstractmethod
    def get_public_key(self) -> bytes:
        """Return the PEM-encoded public key bytes."""
        ...


class EnvironmentKeyProvider(BaseKeyProvider):
    """
    Loads keys from environment variables or file paths.

    Resolution order:
      1. Path from path_var (env var containing a file path)
      2. Inline PEM from env_var (env var with PEM contents)
      3. KeyNotFoundError if neither is set
    """

    def __init__(
        self,
        env_var: str,
        path_var: Optional[str] = None,
        key_id: Optional[str] = None,
    ):
        super().__init__(key_id)
        self.env_var = env_var
        self.path_var = path_var

    def get_private_key(self) -> bytes:
        if self.path_var:
            file_path = os.environ.get(self.path_var)
            if file_path and os.path.isfile(file_path):
                logger.info("Loading key from path: %s", self.path_var)
                with open(file_path, "rb") as f:
                    return f.read()

        pem_data = os.environ.get(self.env_var)
        if pem_data:
            logger.info("Loading key from env var: %s", self.env_var)
            return pem_data.encode("utf-8") if isinstance(pem_data, str) else pem_data

        raise KeyNotFoundError(
            f"Key not found: {self.env_var} not set "
            f"and {self.path_var or 'no path var'} not set/valid"
        )

    def get_public_key(self) -> bytes:
        pub_env_var = f"{self.env_var}_PUBLIC"
        pub_path_var = f"{self.path_var}_PUBLIC" if self.path_var else None
        if pub_path_var:
            file_path = os.environ.get(pub_path_var)
            if file_path and os.path.isfile(file_path):
                with open(file_path, "rb") as f:
                    return f.read()
        pub_data = os.environ.get(pub_env_var)
        if pub_data:
            return pub_data.encode("utf-8") if isinstance(pub_data, str) else pub_data
        raise KeyNotFoundError(f"Public key not found via {pub_env_var}")
