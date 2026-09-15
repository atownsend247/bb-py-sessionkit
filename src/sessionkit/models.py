"""Plain dataclasses passed across the sessionkit API. No storage or web types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class User:
    """An account. The password hash is never carried on this object."""

    email: str
    name: str
    id: int | None = None
    created_at: datetime | None = None
    totp_enabled: bool = False  # derived: has a confirmed TOTP secret


@dataclass
class TotpEnrollment:
    """A pending TOTP setup: the shared secret and its ``otpauth://`` URI."""

    secret: str
    uri: str


@dataclass
class TwoFactorStatus:
    enabled: bool
    recovery_codes_remaining: int


@dataclass
class LoginResult:
    user: User
    token: str
    expires_at: datetime


__all__ = ["User", "TotpEnrollment", "TwoFactorStatus", "LoginResult"]
