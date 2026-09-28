"""AuthService driven end to end against the bundled SqliteAuthStore."""

from __future__ import annotations

import pytest

from sessionkit import (
    AuthenticationError,
    DuplicateUser,
    OtpInvalid,
    OtpLocked,
    OtpRequired,
    UserNotFound,
    ValidationError,
)

import pyotp


def _code(secret: str, clock) -> str:
    return pyotp.TOTP(secret).at(clock())


# --------------------------------------------------------------- accounts


def test_create_login_logout_roundtrip(auth):
    user = auth.create_user("alex@example.com", "password123", name="Alex")
    assert user.id and user.name == "Alex" and user.totp_enabled is False

    result = auth.login("alex@example.com", "password123")
    assert result.user.id == user.id and result.token
    assert auth.user_for_token(result.token).id == user.id

    auth.logout(result.token)
    with pytest.raises(AuthenticationError):
        auth.user_for_token(result.token)


def test_login_records_last_login_at(auth, clock, store):
    user = auth.create_user("alex@example.com", "password123", name="Alex")
    assert user.last_login_at is None
    assert store.get_user_by_id(user.id).last_login_at is None

    first = auth.login("alex@example.com", "password123")
    assert first.user.last_login_at == clock.now
    assert store.get_user_by_id(user.id).last_login_at == clock.now

    clock.advance(3600)
    second = auth.login("alex@example.com", "password123")
    assert second.user.last_login_at == clock.now
    assert store.get_user_by_id(user.id).last_login_at == clock.now


def test_duplicate_email_is_rejected_case_insensitively(auth):
    auth.create_user("alex@example.com", "password123")
    with pytest.raises(DuplicateUser):
        auth.create_user("ALEX@example.com", "password123")


@pytest.mark.parametrize("bad", ["", "   ", "nope", "a@b"])
def test_bad_email_rejected(auth, bad):
    with pytest.raises(ValidationError):
        auth.create_user(bad, "password123")


def test_short_password_rejected(auth):
    with pytest.raises(ValidationError):
        auth.create_user("alex@example.com", "short")


def test_changing_password_revokes_existing_sessions(auth):
    user = auth.create_user("alex@example.com", "password123")
    token = auth.login("alex@example.com", "password123").token
    auth.set_password(user.id, "brand-new-secret")
    with pytest.raises(AuthenticationError):
        auth.user_for_token(token)
    assert auth.login("alex@example.com", "brand-new-secret").token


def test_set_name(auth):
    user = auth.create_user("alex@example.com", "password123", name="Alex")
    auth.set_name(user.id, "Alexandra")
    assert auth.find_user("alex@example.com").name == "Alexandra"


@pytest.mark.parametrize("bad", ["", "   "])
def test_set_name_rejects_empty(auth, bad):
    user = auth.create_user("alex@example.com", "password123")
    with pytest.raises(ValidationError):
        auth.set_name(user.id, bad)


def test_set_email(auth):
    user = auth.create_user("alex@example.com", "password123")
    token = auth.login("alex@example.com", "password123").token

    auth.set_email(user.id, "alexandra@example.com")

    assert auth.find_user("alex@example.com") is None
    assert auth.find_user("alexandra@example.com").id == user.id
    # unlike set_password, an email change does not revoke sessions
    assert auth.user_for_token(token).id == user.id


def test_set_email_self_service_requires_correct_password(auth):
    user = auth.create_user("alex@example.com", "password123")
    with pytest.raises(AuthenticationError):
        auth.set_email(user.id, "alexandra@example.com", current_password="wrong")
    auth.set_email(user.id, "alexandra@example.com", current_password="password123")
    assert auth.find_user("alexandra@example.com").id == user.id


def test_set_email_rejects_duplicate(auth):
    auth.create_user("alex@example.com", "password123")
    other = auth.create_user("sam@example.com", "password123")
    with pytest.raises(DuplicateUser):
        auth.set_email(other.id, "ALEX@example.com")


def test_cannot_delete_the_last_account(auth):
    user = auth.create_user("alex@example.com", "password123")
    with pytest.raises(ValidationError):
        auth.delete_user(user.id)


def test_delete_unknown_account(auth):
    auth.create_user("alex@example.com", "password123")
    with pytest.raises(UserNotFound):
        auth.delete_user("no-such-id")


def test_expired_session_is_rejected_and_purged(auth, clock):
    auth.create_user("alex@example.com", "password123")
    token = auth.login("alex@example.com", "password123").token
    clock.advance(60 * 60 * 24 * 31)  # past the 30-day default
    with pytest.raises(AuthenticationError):
        auth.user_for_token(token)
    auth.purge_expired_sessions()


# ------------------------------------------------------------------- 2FA


@pytest.fixture
def account(auth):
    return auth.create_user("alex@example.com", "password123")


def _enable(auth, clock, user_id):
    enrol = auth.start_totp_enrollment(user_id)
    codes = auth.confirm_totp(user_id, _code(enrol.secret, clock))
    return enrol.secret, codes


def test_enrol_confirm_enables_and_returns_ten_codes(auth, clock, account):
    enrol = auth.start_totp_enrollment(account.id)
    assert enrol.uri.startswith("otpauth://totp/")
    assert auth.two_factor_status(account.id).enabled is False

    codes = auth.confirm_totp(account.id, _code(enrol.secret, clock))
    assert len(codes) == 10
    status = auth.two_factor_status(account.id)
    assert status.enabled is True and status.recovery_codes_remaining == 10


def test_login_needs_a_code_once_enabled(auth, clock, account):
    secret, _ = _enable(auth, clock, account.id)
    with pytest.raises(OtpRequired):
        auth.login("alex@example.com", "password123")
    assert auth.login("alex@example.com", "password123", otp=_code(secret, clock)).token
    with pytest.raises(OtpInvalid):
        auth.login("alex@example.com", "password123", otp="000000")


def test_recovery_code_is_single_use_and_clears_a_lock(auth, clock, account):
    secret, codes = _enable(auth, clock, account.id)
    for _ in range(10):
        with pytest.raises(OtpInvalid):
            auth.login("alex@example.com", "password123", otp="123456")
    with pytest.raises(OtpLocked):
        auth.login("alex@example.com", "password123", otp=_code(secret, clock))

    assert auth.login("alex@example.com", "password123", otp=codes[0]).token
    with pytest.raises(OtpInvalid):
        auth.login("alex@example.com", "password123", otp=codes[0])  # reused
    # the lock cleared: a fresh TOTP now works
    assert auth.login("alex@example.com", "password123", otp=_code(secret, clock)).token


def test_disable_needs_the_password_for_self_service(auth, clock, account):
    _enable(auth, clock, account.id)
    with pytest.raises(AuthenticationError):
        auth.disable_totp(account.id, current_password="wrong")
    auth.disable_totp(account.id, current_password="password123")
    assert auth.two_factor_status(account.id).enabled is False
    assert auth.login("alex@example.com", "password123").token
