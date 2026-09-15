"""Password hashing. The default is Argon2id (``argon2-cffi``); any object with
``hash`` / ``verify`` can be injected instead (tests use a fake)."""

from __future__ import annotations

from typing import Protocol


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password_hash: str, password: str) -> bool: ...


class Argon2Hasher:
    """Thin wrapper over ``argon2.PasswordHasher`` (from ``argon2-cffi``)."""

    def __init__(self) -> None:
        from argon2 import PasswordHasher as _Argon2
        from argon2.exceptions import (
            InvalidHashError,
            VerificationError,
            VerifyMismatchError,
        )

        self._ph = _Argon2()
        self._verify_errors = (VerifyMismatchError, VerificationError, InvalidHashError)

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._ph.verify(password_hash, password)
        except self._verify_errors:
            return False


__all__ = ["PasswordHasher", "Argon2Hasher"]
