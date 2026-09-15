from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sessionkit import AuthService, SqliteAuthStore
from sessionkit.sqlite_store import connect



class FakeClock:
    """Controllable clock so timestamp assertions are deterministic."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class FakeHasher:
    """Fast, deterministic stand-in for Argon2."""

    def hash(self, password: str) -> str:
        return f"fakehash:{password}"

    def verify(self, password_hash: str, password: str) -> bool:
        return password_hash == f"fakehash:{password}"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc))


@pytest.fixture
def store() -> SqliteAuthStore:
    conn = connect(":memory:", check_same_thread=False)
    try:
        yield SqliteAuthStore(conn)
    finally:
        conn.close()


@pytest.fixture
def auth(store, clock) -> AuthService:
    return AuthService(store, hasher=FakeHasher(), clock=clock)
