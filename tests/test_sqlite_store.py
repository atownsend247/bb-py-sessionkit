from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sessionkit import AuthStore, DuplicateUser, SqliteAuthStore
from sessionkit.sqlite_store import connect, ensure_schema


def test_ensure_schema_is_idempotent():
    conn = connect(":memory:")
    try:
        ensure_schema(conn)  # second call must not raise
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"users", "sessions", "recovery_codes"} <= tables
    finally:
        conn.close()


def test_store_satisfies_the_protocol(store):
    assert isinstance(store, AuthStore)


def test_user_crud_and_totp_columns(store):
    user = store.add_user("a@b.com", "A", "hash")
    assert store.count_users() == 1
    assert store.get_user_by_id(user.id).email == "a@b.com"
    assert store.get_user_by_email("A@B.COM").id == user.id
    assert store.get_password_hash(user.id) == "hash"

    store.set_password_hash(user.id, "hash2")
    assert store.get_password_hash(user.id) == "hash2"

    assert store.get_totp(user.id) == (None, None, 0)
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.set_totp(user.id, secret="S", confirmed_at=when)
    secret, confirmed, failures = store.get_totp(user.id)
    assert (secret, confirmed, failures) == ("S", when, 0)
    assert store.get_user_by_id(user.id).totp_enabled is True

    store.bump_totp_failures(user.id)
    store.bump_totp_failures(user.id)
    assert store.get_totp(user.id)[2] == 2
    store.reset_totp_failures(user.id)
    assert store.get_totp(user.id)[2] == 0

    store.delete_user(user.id)
    assert store.count_users() == 0


def test_duplicate_email_raises(store):
    store.add_user("a@b.com", "A", "h")
    with pytest.raises(DuplicateUser):
        store.add_user("a@b.com", "A2", "h2")


def test_recovery_codes_replace_consume_count(store):
    user = store.add_user("a@b.com", "A", "h")
    store.replace_recovery_codes(user.id, ["h1", "h2", "h3"])
    assert store.count_unused_recovery_codes(user.id) == 3

    now = datetime.now(timezone.utc)
    assert store.consume_recovery_code(user.id, "h2", now) is True
    assert store.consume_recovery_code(user.id, "h2", now) is False  # already used
    assert store.count_unused_recovery_codes(user.id) == 2

    store.replace_recovery_codes(user.id, ["x1"])  # replaces the whole set
    assert store.count_unused_recovery_codes(user.id) == 1


def test_sessions_lifecycle(store):
    user = store.add_user("a@b.com", "A", "h")
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    store.add_session("tok", user.id, now + timedelta(days=1))
    assert store.get_session_user_id("tok", now) == user.id
    assert store.get_session_user_id("tok", now + timedelta(days=2)) is None  # expired
    assert store.get_session_user_id("missing", now) is None

    store.add_session("t2", user.id, now + timedelta(days=1))
    store.delete_session("tok")
    assert store.get_session_user_id("tok", now) is None
    store.delete_sessions_for_user(user.id)
    assert store.get_session_user_id("t2", now) is None

    store.add_session("old", user.id, now - timedelta(days=1))
    store.purge_expired_sessions(now)
    assert store.get_session_user_id("old", now - timedelta(days=2)) is None


def test_open_classmethod_builds_a_ready_store(tmp_path):
    with SqliteAuthStore.open(str(tmp_path / "auth.db")) as store:
        store.add_user("a@b.com", "A", "h")
        assert store.count_users() == 1


def test_close_releases_the_connection(tmp_path):
    store = SqliteAuthStore.open(str(tmp_path / "auth.db"))
    store.add_user("a@b.com", "A", "h")
    store.close()
    with pytest.raises(Exception):  # sqlite3.ProgrammingError on a closed connection
        store.count_users()


def test_close_is_idempotent(tmp_path):
    store = SqliteAuthStore.open(str(tmp_path / "auth.db"))
    store.close()
    store.close()  # must not raise


def test_used_as_a_context_manager_closes_on_exit(tmp_path):
    with SqliteAuthStore.open(str(tmp_path / "auth.db")) as store:
        store.add_user("a@b.com", "A", "h")
        assert store.count_users() == 1

    with pytest.raises(Exception):
        store.count_users()


def test_context_manager_closes_even_on_an_exception(tmp_path):
    store = SqliteAuthStore.open(str(tmp_path / "auth.db"))
    with pytest.raises(ValueError):
        with store:
            raise ValueError("boom")

    with pytest.raises(Exception):
        store.count_users()
