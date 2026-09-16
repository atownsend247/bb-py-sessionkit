"""Accounts, opaque server-side sessions, and opt-in TOTP two-factor auth.

Passwords are hashed with Argon2id by default. Session tokens are random and
only their SHA-256 is stored, so logout / revocation actually work. TOTP is
per-account with one-time recovery codes and a lockout after repeated bad codes.

The service holds no state and touches storage only through :class:`AuthStore`;
the clock is injectable so tests are deterministic. Account ids are opaque
strings (the bundled store uses a UUID4) - never parsed, ordered, or compared
as numbers here.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable

import pyotp

from .errors import (
    AuthenticationError,
    OtpInvalid,
    OtpLocked,
    OtpRequired,
    UserNotFound,
    ValidationError,
)
from .hashing import Argon2Hasher, PasswordHasher
from .models import LoginResult, TotpEnrollment, TwoFactorStatus, User
from .store import AuthStore

__all__ = ["AuthService", "DEFAULT_SESSION_DAYS", "DEFAULT_ISSUER"]

DEFAULT_SESSION_DAYS = 30
DEFAULT_ISSUER = "sessionkit"

_MIN_PASSWORD = 8
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_OTP_MAX_FAILURES = 10  # consecutive bad codes before TOTP is locked
_RECOVERY_CODE_COUNT = 10
# no i/l/o/0/1 - unambiguous when written on paper
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_LOCKED_MSG = (
    "too many incorrect codes - use a recovery code, or ask an admin to reset "
    "two-factor for this account"
)


def _new_recovery_code() -> str:
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def _hash_recovery(code: str) -> str:
    normalised = code.strip().lower().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _clean_email(email: object) -> str:
    if not isinstance(email, str) or not email.strip():
        raise ValidationError("email is required")
    value = email.strip()
    if not _EMAIL_RE.match(value):
        raise ValidationError("that does not look like an email address")
    return value


def _check_password(password: object) -> None:
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD:
        raise ValidationError(f"password must be at least {_MIN_PASSWORD} characters")


class AuthService:
    def __init__(
        self,
        store: AuthStore,
        *,
        hasher: PasswordHasher | None = None,
        clock: Callable[[], datetime] | None = None,
        session_days: int = DEFAULT_SESSION_DAYS,
        issuer: str = DEFAULT_ISSUER,
    ) -> None:
        self._repo = store
        self._hasher = hasher or Argon2Hasher()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._session_days = session_days
        self._issuer = issuer

    # ------------------------------------------------------------------ users
    def has_users(self) -> bool:
        return self._repo.count_users() > 0

    def list_users(self) -> list[User]:
        return self._repo.list_users()

    def find_user(self, email: str) -> User | None:
        return self._repo.get_user_by_email(email.strip()) if email.strip() else None

    def create_user(self, email: str, password: str, *, name: str | None = None) -> User:
        clean_email = _clean_email(email)
        _check_password(password)
        display = name.strip() if isinstance(name, str) and name.strip() else clean_email.split("@")[0]
        return self._repo.add_user(clean_email, display, self._hasher.hash(password))

    def set_password(self, user_id: str, password: str) -> None:
        self._require_user(user_id)
        _check_password(password)
        self._repo.set_password_hash(user_id, self._hasher.hash(password))
        self._repo.delete_sessions_for_user(user_id)  # force re-login everywhere

    def delete_user(self, user_id: str) -> None:
        self._require_user(user_id)
        if self._repo.count_users() <= 1:
            raise ValidationError("cannot delete the last remaining user")
        self._repo.delete_sessions_for_user(user_id)
        self._repo.delete_user(user_id)

    # ---------------------------------------------------------- two-factor
    def two_factor_status(self, user_id: str) -> TwoFactorStatus:
        _, confirmed_at, _ = self._repo.get_totp(user_id)
        return TwoFactorStatus(
            enabled=confirmed_at is not None,
            recovery_codes_remaining=self._repo.count_unused_recovery_codes(user_id),
        )

    def start_totp_enrollment(self, user_id: str) -> TotpEnrollment:
        """Generate a fresh (unconfirmed) secret and its provisioning URI."""
        user = self._require_user(user_id)
        _, confirmed_at, _ = self._repo.get_totp(user_id)
        if confirmed_at is not None:
            raise ValidationError("two-factor is already enabled; disable it first")
        secret = pyotp.random_base32()
        self._repo.set_totp(user_id, secret=secret, confirmed_at=None)
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name=self._issuer
        )
        return TotpEnrollment(secret=secret, uri=uri)

    def confirm_totp(self, user_id: str, otp: str) -> list[str]:
        """Verify a code against the pending secret, enable 2FA, return recovery codes."""
        self._require_user(user_id)
        secret, confirmed_at, _ = self._repo.get_totp(user_id)
        if secret is None:
            raise ValidationError("start two-factor setup first")
        if confirmed_at is not None:
            raise ValidationError("two-factor is already enabled")
        code = otp.strip().replace(" ", "") if isinstance(otp, str) else ""
        if not (code.isdigit() and len(code) == 6 and self._verify_totp(secret, code)):
            raise OtpInvalid("incorrect authentication code")
        self._repo.set_totp(user_id, secret=secret, confirmed_at=self._clock())
        self._repo.reset_totp_failures(user_id)
        return self._issue_recovery_codes(user_id)

    def disable_totp(self, user_id: str, *, current_password: str | None = None) -> None:
        """Turn 2FA off. ``current_password`` is checked for self-service; an
        admin CLI calls this without one."""
        self._require_user(user_id)
        if current_password is not None:
            stored = self._repo.get_password_hash(user_id)
            if stored is None or not self._hasher.verify(stored, current_password):
                raise AuthenticationError("incorrect password")
        self._repo.set_totp(user_id, secret=None, confirmed_at=None)
        self._repo.reset_totp_failures(user_id)
        self._repo.replace_recovery_codes(user_id, [])

    def regenerate_recovery_codes(self, user_id: str, current_password: str) -> list[str]:
        self._require_user(user_id)
        _, confirmed_at, _ = self._repo.get_totp(user_id)
        if confirmed_at is None:
            raise ValidationError("two-factor is not enabled")
        stored = self._repo.get_password_hash(user_id)
        if stored is None or not self._hasher.verify(stored, current_password):
            raise AuthenticationError("incorrect password")
        return self._issue_recovery_codes(user_id)

    def _issue_recovery_codes(self, user_id: str) -> list[str]:
        codes = [_new_recovery_code() for _ in range(_RECOVERY_CODE_COUNT)]
        self._repo.replace_recovery_codes(user_id, [_hash_recovery(c) for c in codes])
        return codes

    def _verify_totp(self, secret: str, code: str) -> bool:
        return pyotp.TOTP(secret).verify(
            code, for_time=self._clock(), valid_window=1
        )

    def _check_second_factor(
        self, user_id: str, secret: str, failures: int, otp: str | None
    ) -> None:
        locked = failures >= _OTP_MAX_FAILURES
        code = otp.strip() if isinstance(otp, str) else ""
        if not code:
            raise OtpLocked(_LOCKED_MSG) if locked else OtpRequired(
                "enter the 6-digit code from your authenticator app"
            )
        digits = code.replace(" ", "")
        if digits.isdigit() and len(digits) == 6:
            if locked:
                raise OtpLocked(_LOCKED_MSG)
            if self._verify_totp(secret, digits):
                self._repo.reset_totp_failures(user_id)
                return
            self._repo.bump_totp_failures(user_id)
            raise OtpInvalid("incorrect authentication code")
        # a recovery code - accepted even when locked, and clears the lock
        if self._repo.consume_recovery_code(
            user_id, _hash_recovery(code), self._clock()
        ):
            self._repo.reset_totp_failures(user_id)
            return
        if not locked:
            self._repo.bump_totp_failures(user_id)
        raise OtpInvalid("incorrect authentication code")

    # --------------------------------------------------------------- sessions
    def login(self, email: str, password: str, otp: str | None = None) -> LoginResult:
        lookup = email.strip() if isinstance(email, str) else ""
        user = self._repo.get_user_by_email(lookup) if lookup else None
        stored = self._repo.get_password_hash(user.id) if user is not None else None
        if user is None or stored is None or not self._hasher.verify(stored, password):
            raise AuthenticationError("incorrect email or password")

        secret, confirmed_at, failures = self._repo.get_totp(user.id)
        if confirmed_at is not None:
            self._check_second_factor(user.id, secret, failures, otp)

        now = self._clock()
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(days=self._session_days)
        self._repo.add_session(_token_hash(token), user.id, expires_at)
        return LoginResult(user=user, token=token, expires_at=expires_at)

    def user_for_token(self, token: str | None) -> User:
        if not token:
            raise AuthenticationError("not authenticated")
        user_id = self._repo.get_session_user_id(_token_hash(token), self._clock())
        user = self._repo.get_user_by_id(user_id) if user_id is not None else None
        if user is None:
            raise AuthenticationError("session expired or invalid")
        return user

    def logout(self, token: str | None) -> None:
        if token:
            self._repo.delete_session(_token_hash(token))

    def purge_expired_sessions(self) -> None:
        self._repo.purge_expired_sessions(self._clock())

    # ----------------------------------------------------------------- helper
    def _require_user(self, user_id: str) -> User:
        user = self._repo.get_user_by_id(user_id)
        if user is None:
            raise UserNotFound(f"No user with id {user_id}")
        return user
