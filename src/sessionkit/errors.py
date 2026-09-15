"""Exceptions raised by :class:`sessionkit.AuthService`.

All inherit :class:`AuthError`. A web layer maps them to status codes; the
suggested mapping is in each docstring.
"""

from __future__ import annotations


class AuthError(Exception):
    """Base class for every sessionkit error."""


class AuthenticationError(AuthError):
    """Bad credentials, or a missing / expired / unknown session. -> 401"""


class OtpRequired(AuthenticationError):
    """Password was correct but this account needs a two-factor code. -> 401"""


class OtpLocked(AuthenticationError):
    """Two-factor is locked after too many failed codes. -> 401"""


class OtpInvalid(AuthError):
    """A supplied TOTP or recovery code did not match. -> 422 (401 at login)."""


class UserNotFound(AuthError):
    """No account with the given id or email. -> 404"""


class DuplicateUser(AuthError):
    """An account with the given email already exists. -> 409"""


class ValidationError(AuthError):
    """An email / password / 2FA-state rule was broken. -> 422"""


__all__ = [
    "AuthError",
    "AuthenticationError",
    "OtpRequired",
    "OtpLocked",
    "OtpInvalid",
    "UserNotFound",
    "DuplicateUser",
    "ValidationError",
]
