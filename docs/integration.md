# Integration guide

## Quickstart

```python
from sessionkit import AuthService, SqliteAuthStore

with SqliteAuthStore.open("auth.db") as store:     # or ":memory:"
    auth = AuthService(store)
    user = auth.create_user("you@example.com", "correct horse battery staple")

    result = auth.login("you@example.com", "correct horse battery staple")
    # result.token   -> opaque; put it in a cookie / header
    auth.user_for_token(result.token)                        # -> User, or raises
    auth.logout(result.token)
```

Construct **one `AuthService`** (and one store) for the life of your process
— at app startup, not per-request. Both are cheap to hold: `AuthService` is
stateless, and `SqliteAuthStore` is safe to share across a thread pool (see
[architecture.md](architecture.md#threading)).

## FastAPI example (cookie session, 2FA, error mapping)

This is [`examples/fastapi_app.py`](../examples/fastapi_app.py), embedded
verbatim — not a hand-copied snippet that can quietly drift. Two tests keep
it honest: `tests/test_example_fastapi.py` runs it against a real
`fastapi.testclient.TestClient` (login, a wrong password, 2FA setup + a wrong
code, a full 2FA round trip, logout, the 401 afterwards), and
`tests/test_docs_examples_in_sync.py` fails CI if this code block and the
file it's copied from ever disagree. Both run as part of the normal `pytest`
suite — see [development.md](development.md#keeping-the-example-honest).

<!-- BEGIN examples/fastapi_app.py -->
```python
"""A complete FastAPI integration: cookie session, 2FA, error mapping.

This is the canonical source for the example in docs/integration.md - the
markdown embeds this file's contents verbatim, and
tests/test_docs_examples_in_sync.py fails CI if the two ever drift apart.
tests/test_example_fastapi.py runs it against a real TestClient, so this
example is exercised by the normal test suite, not just eyeballed.

Edit this file, not the code fence in the docs - see
docs/development.md#keeping-the-example-honest.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from sessionkit import (
    AuthenticationError,
    AuthError,
    AuthService,
    DuplicateUser,
    OtpInvalid,
    OtpLocked,
    OtpRequired,
    SqliteAuthStore,
    UserNotFound,
    ValidationError,
)

SESSION_COOKIE = "session_token"

# One place maps every AuthError subclass to a status code. Order doesn't
# matter here (each key is checked with isinstance, first match wins) as long
# as OtpInvalid has its own entry - it's the one AuthError subclass that is
# NOT an AuthenticationError, so it won't be caught by that entry.
_ERROR_STATUS: dict[type[AuthError], int] = {
    AuthenticationError: 401,   # covers OtpRequired / OtpLocked too
    OtpInvalid: 422,            # not an AuthenticationError subclass - map it explicitly
    UserNotFound: 404,
    DuplicateUser: 409,
    ValidationError: 422,
}


def create_app(auth: AuthService) -> FastAPI:
    app = FastAPI()

    async def _handle_auth_error(_request: Request, exc: AuthError) -> JSONResponse:
        status = next((s for t, s in _ERROR_STATUS.items() if isinstance(exc, t)), 400)
        return JSONResponse(status_code=status, content={"detail": str(exc)})

    for exc_type in _ERROR_STATUS:
        app.add_exception_handler(exc_type, _handle_auth_error)

    def current_user(request: Request):
        # AuthenticationError propagates to the handler above -> 401
        return auth.user_for_token(request.cookies.get(SESSION_COOKIE))

    @app.post("/auth/login")
    def login(payload: dict, response: Response):
        try:
            result = auth.login(payload["email"], payload["password"], otp=payload.get("otp"))
        except OtpRequired as exc:
            return JSONResponse(status_code=401, content={"detail": str(exc), "otp_required": True})
        except OtpLocked as exc:
            return JSONResponse(status_code=401, content={"detail": str(exc), "otp_locked": True})
        except OtpInvalid as exc:
            # a bad 2FA code AT LOGIN is an authentication failure (401) -
            # the general map above gives OtpInvalid 422 everywhere else
            # (e.g. /auth/2fa/confirm below), which is the right status there
            return JSONResponse(status_code=401, content={"detail": str(exc)})
        response.set_cookie(SESSION_COOKIE, result.token, httponly=True, samesite="lax")
        return {"email": result.user.email}

    @app.post("/auth/logout", status_code=204)
    def logout(request: Request, response: Response):
        auth.logout(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE)

    @app.get("/auth/me")
    def me(user=Depends(current_user)):
        return {"email": user.email, "totp_enabled": user.totp_enabled}

    @app.post("/auth/2fa/setup")
    def setup_2fa(user=Depends(current_user)):
        enrol = auth.start_totp_enrollment(user.id)
        return {"secret": enrol.secret, "otpauth_uri": enrol.uri}

    @app.post("/auth/2fa/confirm")
    def confirm_2fa(payload: dict, user=Depends(current_user)):
        # a wrong code here hits the general map -> 422 (OtpInvalid, not
        # AuthenticationError) - this is enrolment, not a login attempt
        codes = auth.confirm_totp(user.id, payload["otp"])
        return {"recovery_codes": codes}

    return app
```
<!-- END examples/fastapi_app.py -->

Wire it up at startup:

```python
store = SqliteAuthStore.open("auth.db")   # or your own AuthStore - see below
auth = AuthService(store)
app = create_app(auth)
```

Points worth calling out:

- **`current_user` is a plain dependency function**, not a class or anything
  sessionkit provides — `AuthService.user_for_token` already raises
  `AuthenticationError` for a missing/expired/invalid token, so the
  dependency is one line and the status code comes from the error map like
  everything else.
- **`login` has its own `except` clauses** rather than relying purely on the
  general map, because `OtpRequired` / `OtpLocked` responses carry extra
  fields (`otp_required` / `otp_locked`) a login form needs to decide what to
  show the user next — the general map only ever returns `{"detail": ...}`.
- The **`OtpInvalid` split** (401 from `login`, 422 from `/2fa/confirm`) is
  the one detail worth double-checking if you copy this pattern — see
  [architecture.md](architecture.md#errors) for why it's not just a style
  choice.

### Error mapping

The table this example's `_ERROR_STATUS` implements — reproduced from
[architecture.md](architecture.md#errors):

| Exception | Status | Note |
|---|---|---|
| `AuthenticationError` (+ `OtpRequired`, `OtpLocked`) | 401 | |
| `OtpInvalid` | 422, except **401 when raised from `login()`** | needs its own map entry - it isn't an `AuthenticationError` |
| `UserNotFound` | 404 | |
| `DuplicateUser` | 409 | |
| `ValidationError` | 422 | |

## Bring your own storage

`SqliteAuthStore` is a convenience, not a requirement. Implement `AuthStore`
(`sessionkit.store.AuthStore`, `runtime_checkable`) against whatever your app
already uses, and pass that to `AuthService` instead:

```python
from sessionkit import AuthService, User

class MyOrmAuthStore:
    """Sketch - wire each method to your ORM/DB of choice. Every method sessionkit
    calls is listed in sessionkit/store.py; this is not the full set."""

    def add_user(self, email: str, name: str, password_hash: str) -> User:
        row = MyUserModel.objects.create(email=email, name=name, password_hash=password_hash)
        return User(id=row.id, email=row.email, name=row.name, created_at=row.created_at)

    def get_user_by_email(self, email: str) -> User | None:
        row = MyUserModel.objects.filter(email__iexact=email).first()
        return _to_user(row) if row else None

    # ... the remaining ~18 methods (see sessionkit/store.py) ...

auth = AuthService(MyOrmAuthStore())
```

No inheritance needed — `AuthStore` is a `Protocol`, so anything with the
right method names and signatures satisfies it structurally. This is exactly
how the app sessionkit was extracted from does it: its own SQLite repository
class (which already persists rooms/boxes/items) gained the `AuthStore`
methods and now doubles as the store, with no schema changes and no
inheritance relationship to anything in sessionkit.

A couple of things worth getting right in your own implementation:

- **Raise `DuplicateUser`** from `add_user` on a clashing email (sessionkit
  never checks uniqueness itself — that's a storage-layer constraint).
- **`get_user_by_email` must be case-insensitive** (`AuthService` doesn't
  lower-case for you; `SqliteAuthStore` uses `COLLATE NOCASE`).
- **Session lookups are also expiry checks** — `get_session_user_id(token_hash,
  now)` should return `None` for an existing-but-expired session, not the
  user id (see `sqlite_store.py` for the reference behaviour).

## Testing your integration

Two options, both fast (no real Argon2 hashing, no real clock):

```python
from sessionkit import AuthService, SqliteAuthStore

def test_something():
    with SqliteAuthStore.open(":memory:") as store:
        auth = AuthService(store)
        # exercise your integration against `auth`
```

or, for a pure unit test of *your* code with no SQLite at all, hand-roll a
minimal fake covering only the methods your code path actually calls. This is
what sessionkit's own tests do for the password hasher — a `FakeHasher` with
just `hash`/`verify` (`PasswordHasher` is a two-method `Protocol`, so a fake
satisfies it the same structural way `SqliteAuthStore` satisfies `AuthStore`)
stands in for the real `Argon2Hasher`, which is intentionally slow. The same
idea works for a partial `AuthStore` fake if you don't need the whole
Protocol for a given test — `AuthService(fake_store, hasher=FakeHasher())`.

For a web framework integration, `AuthService` doesn't care that it's being
called from a test client vs. a real request — the FastAPI example above was
verified exactly this way, with `fastapi.testclient.TestClient` and an
in-memory store, no real HTTP server involved.

## CLI

`sessionkit …` / `python -m sessionkit …` manages accounts directly against a
`SqliteAuthStore` file — see the root [README.md](../README.md#cli). It's a
convenience for `SqliteAuthStore`-backed apps; a host with its own `AuthStore`
implementation typically ships its own equivalent wrapper instead (the app
sessionkit was extracted from does exactly that — `inventory.cli.users`).
