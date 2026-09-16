"""A bundled :class:`~sessionkit.store.AuthStore` backed by SQLite.

Self-contained: it owns its three tables and creates them with
:func:`ensure_schema`. A host app that already has its own database and
persistence layer (like the inventory app) can implement ``AuthStore`` itself
and skip this entirely.

One connection is shared and every call is serialised on a lock, matching
``sqlite3.threadsafety == 1``. Account ids are UUID4 strings generated here
(not a database autoincrement) - opaque and non-sequential on purpose, so
nothing about an id reveals creation order or how many accounts exist.
"""

from __future__ import annotations

import functools
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, TypeVar

from .errors import DuplicateUser
from .models import User

_R = TypeVar("_R")

AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                 TEXT PRIMARY KEY,
    email              TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name               TEXT NOT NULL,
    password_hash      TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    totp_secret        TEXT,
    totp_confirmed_at  TEXT,
    totp_failures      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes(user_id);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the ``users`` / ``sessions`` / ``recovery_codes`` tables if absent."""
    conn.executescript(AUTH_SCHEMA)
    conn.commit()


def connect(db_path: str = "auth.db", *, check_same_thread: bool = False) -> sqlite3.Connection:
    """Open a connection with foreign keys on, row access by name, and (for a
    real file) WAL journalling. Runs :func:`ensure_schema`.

    ``check_same_thread`` defaults to ``False``: every ``SqliteAuthStore``
    method is already serialised on its own lock (see the module docstring),
    so the connection is safe to share across threads - which a real server
    (FastAPI's threaded request handling, a WSGI app, ...) needs. Pass
    ``True`` back if you specifically want sqlite3's single-thread guard.
    """
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    ensure_schema(conn)
    return conn


def _locked(method: Callable[..., _R]) -> Callable[..., _R]:
    @functools.wraps(method)
    def wrapper(self: "SqliteAuthStore", *args: object, **kwargs: object) -> _R:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _user_from_row(row: sqlite3.Row) -> User:
    keys = row.keys()
    return User(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        created_at=datetime.fromisoformat(row["created_at"]),
        totp_enabled=(
            "totp_confirmed_at" in keys and row["totp_confirmed_at"] is not None
        ),
    )


class SqliteAuthStore:
    """``AuthStore`` over one shared :class:`sqlite3.Connection`."""

    def __init__(self, conn: sqlite3.Connection, *, lock: "threading.Lock | None" = None) -> None:
        self._conn = conn
        self._lock = lock or threading.Lock()

    @classmethod
    def open(cls, db_path: str = "auth.db", *, check_same_thread: bool = False) -> "SqliteAuthStore":
        return cls(connect(db_path, check_same_thread=check_same_thread))

    def close(self) -> None:
        """Close the underlying connection. Idempotent - closing twice is a
        no-op, matching :meth:`sqlite3.Connection.close`."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SqliteAuthStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---- accounts ---------------------------------------------------
    @_locked
    def add_user(self, email: str, name: str, password_hash: str) -> User:
        new_id = str(uuid.uuid4())
        created_at = _iso(datetime.now(timezone.utc))
        try:
            self._conn.execute(
                "INSERT INTO users (id, email, name, password_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (new_id, email, name, password_hash, created_at),
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateUser(f"A user with email {email!r} already exists") from exc
        self._conn.commit()
        return User(
            id=new_id,
            email=email,
            name=name,
            created_at=datetime.fromisoformat(created_at),
        )

    @_locked
    def get_user_by_id(self, user_id: str) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return _user_from_row(row) if row is not None else None

    @_locked
    def get_user_by_email(self, email: str) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()
        return _user_from_row(row) if row is not None else None

    @_locked
    def get_password_hash(self, user_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return row["password_hash"] if row is not None else None

    @_locked
    def set_password_hash(self, user_id: str, password_hash: str) -> None:
        self._conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )
        self._conn.commit()

    @_locked
    def list_users(self) -> list[User]:
        rows = self._conn.execute("SELECT * FROM users ORDER BY email COLLATE NOCASE")
        return [_user_from_row(r) for r in rows]

    @_locked
    def delete_user(self, user_id: str) -> None:
        self._conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        self._conn.commit()

    @_locked
    def count_users(self) -> int:
        (count,) = self._conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return count

    # ---- two-factor ------------------------------------------------
    @_locked
    def get_totp(self, user_id: str) -> tuple[str | None, datetime | None, int]:
        row = self._conn.execute(
            "SELECT totp_secret, totp_confirmed_at, totp_failures FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return (None, None, 0)
        confirmed = row["totp_confirmed_at"]
        return (
            row["totp_secret"],
            datetime.fromisoformat(confirmed) if confirmed is not None else None,
            row["totp_failures"] or 0,
        )

    @_locked
    def set_totp(
        self, user_id: str, *, secret: str | None, confirmed_at: datetime | None
    ) -> None:
        self._conn.execute(
            "UPDATE users SET totp_secret = ?, totp_confirmed_at = ? WHERE id = ?",
            (secret, _iso(confirmed_at) if confirmed_at is not None else None, user_id),
        )
        self._conn.commit()

    @_locked
    def bump_totp_failures(self, user_id: str) -> None:
        self._conn.execute(
            "UPDATE users SET totp_failures = totp_failures + 1 WHERE id = ?", (user_id,)
        )
        self._conn.commit()

    @_locked
    def reset_totp_failures(self, user_id: str) -> None:
        self._conn.execute(
            "UPDATE users SET totp_failures = 0 WHERE id = ?", (user_id,)
        )
        self._conn.commit()

    @_locked
    def replace_recovery_codes(self, user_id: str, code_hashes: list[str]) -> None:
        self._conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        self._conn.executemany(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            [(user_id, h) for h in code_hashes],
        )
        self._conn.commit()

    @_locked
    def consume_recovery_code(
        self, user_id: str, code_hash: str, used_at: datetime
    ) -> bool:
        cur = self._conn.execute(
            "UPDATE recovery_codes SET used_at = ? "
            "WHERE id = (SELECT id FROM recovery_codes "
            "            WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1)",
            (_iso(used_at), user_id, code_hash),
        )
        self._conn.commit()
        return cur.rowcount > 0

    @_locked
    def count_unused_recovery_codes(self, user_id: str) -> int:
        (count,) = self._conn.execute(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        ).fetchone()
        return count

    # ---- sessions ------------------------------------------------
    @_locked
    def add_session(self, token_hash: str, user_id: str, expires_at: datetime) -> None:
        self._conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_hash, user_id, _iso(datetime.now(timezone.utc)), _iso(expires_at)),
        )
        self._conn.commit()

    @_locked
    def get_session_user_id(self, token_hash: str, now: datetime) -> str | None:
        row = self._conn.execute(
            "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= now:
            return None
        return row["user_id"]

    @_locked
    def delete_session(self, token_hash: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        self._conn.commit()

    @_locked
    def delete_sessions_for_user(self, user_id: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        self._conn.commit()

    @_locked
    def purge_expired_sessions(self, now: datetime) -> None:
        self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_iso(now),))
        self._conn.commit()


__all__ = ["SqliteAuthStore", "AUTH_SCHEMA", "ensure_schema", "connect"]
