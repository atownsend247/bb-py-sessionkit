"""sessionkit - reusable accounts, sessions and TOTP two-factor auth.

    from sessionkit import AuthService, SqliteAuthStore

    with SqliteAuthStore.open("auth.db") as store:      # or SqliteAuthStore.open(...).close()
        auth = AuthService(store)
        user = auth.create_user("you@example.com", "correct horse battery staple")
        result = auth.login("you@example.com", "correct horse battery staple")
        #   -> result.token  (opaque; store its cookie, pass it to user_for_token)

The service is storage-agnostic: point it at :class:`SqliteAuthStore` or any
object satisfying :class:`AuthStore`. Nothing here imports a web framework or a
host application. See ``README.md``.
"""

from __future__ import annotations

from .errors import (
    AuthenticationError,
    AuthError,
    DuplicateUser,
    OtpInvalid,
    OtpLocked,
    OtpRequired,
    UserNotFound,
    ValidationError,
)
from .hashing import Argon2Hasher, PasswordHasher
from .models import LoginResult, TotpEnrollment, TwoFactorStatus, User
from .service import DEFAULT_ISSUER, DEFAULT_SESSION_DAYS, AuthService
from .sqlite_store import AUTH_SCHEMA, SqliteAuthStore, ensure_schema
from .store import AuthStore

__version__ = "0.1.2"

__all__ = [
    "__version__",
    "AuthService",
    "AuthStore",
    "SqliteAuthStore",
    "AUTH_SCHEMA",
    "ensure_schema",
    "Argon2Hasher",
    "PasswordHasher",
    "User",
    "TotpEnrollment",
    "TwoFactorStatus",
    "LoginResult",
    "DEFAULT_SESSION_DAYS",
    "DEFAULT_ISSUER",
    # errors
    "AuthError",
    "AuthenticationError",
    "OtpRequired",
    "OtpLocked",
    "OtpInvalid",
    "UserNotFound",
    "DuplicateUser",
    "ValidationError",
]
