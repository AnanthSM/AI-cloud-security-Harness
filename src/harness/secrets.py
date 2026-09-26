import os
from typing import Protocol

from harness.errors import Forbidden


class SecretProvider(Protocol):
    def get_secret(self, name: str) -> str: ...


class EnvironmentSecretProvider:
    def get_secret(self, name: str) -> str:
        value = os.environ.get(name)
        if not value:
            raise Forbidden("Required credential is not configured")
        return value
