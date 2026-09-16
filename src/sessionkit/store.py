"""The persistence contract :class:`sessionkit.AuthService` depends on.

Any object with these methods works - :class:`sessionkit.SqliteAuthStore` is the
bundled implementation; a host app can point the service at its own store (the
inventory app's ``SqliteRepository`` satisfies this protocol structurally).
Implementations do plain persistence only; all rules live in the service.

``user_id`` is an opaque string (``SqliteAuthStore`` uses a UUID4) - never
assume it's numeric, sequential, or safe to expose ordering/count information
through.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from .models import User


@runtime_checkable
class AuthStore(Protocol):
    # ---- accounts ---------------------------------------------------
    def add_user(self, email: str, name: str, password_hash: str) -> User:
        """Insert an account (generating its id); raise ``DuplicateUser`` on a
        clashing email."""

    def get_user_by_id(self, user_id: str) -> User | None: ...

    def get_user_by_email(self, email: str) -> User | None:
        """Match on email, case-insensitively."""

    def get_password_hash(self, user_id: str) -> str | None: ...

    def set_password_hash(self, user_id: str, password_hash: str) -> None: ...

    def list_users(self) -> list[User]: ...

    def delete_user(self, user_id: str) -> None: ...

    def count_users(self) -> int: ...

    # ---- two-factor ------------------------------------------------
    def get_totp(self, user_id: str) -> tuple[str | None, datetime | None, int]:
        """``(secret, confirmed_at, consecutive_failures)`` for the account."""

    def set_totp(
        self, user_id: str, *, secret: str | None, confirmed_at: datetime | None
    ) -> None:
        """Store (or clear, with ``secret=None``) the account's TOTP secret."""

    def bump_totp_failures(self, user_id: str) -> None: ...

    def reset_totp_failures(self, user_id: str) -> None: ...

    def replace_recovery_codes(self, user_id: str, code_hashes: list[str]) -> None:
        """Delete the account's recovery codes and insert these fresh hashes."""

    def consume_recovery_code(
        self, user_id: str, code_hash: str, used_at: datetime
    ) -> bool:
        """Mark one matching unused code used; True if one was found."""

    def count_unused_recovery_codes(self, user_id: str) -> int: ...

    # ---- sessions ------------------------------------------------
    def add_session(
        self, token_hash: str, user_id: str, expires_at: datetime
    ) -> None: ...

    def get_session_user_id(self, token_hash: str, now: datetime) -> str | None:
        """Account id for a live (unexpired) session, or None."""

    def delete_session(self, token_hash: str) -> None: ...

    def delete_sessions_for_user(self, user_id: str) -> None: ...

    def purge_expired_sessions(self, now: datetime) -> None: ...


__all__ = ["AuthStore"]
