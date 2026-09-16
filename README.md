# sessionkit

[![Latest tag](https://img.shields.io/github/v/tag/atownsend247/bb-py-sessionkit?label=latest)](https://github.com/atownsend247/bb-py-sessionkit/tags)

Accounts, opaque server-side sessions, and opt-in TOTP two-factor auth with
one-time recovery codes. Framework-agnostic — no web framework, no ORM, no
assumptions about your database beyond an `AuthStore` you provide.

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

(`SqliteAuthStore` also works without the `with`: call `store.close()`
yourself when you're done with it — e.g. a long-lived server process that
opens the store once at startup.)

Two-factor:

```python
enrol = auth.start_totp_enrollment(user.id)      # -> secret + otpauth:// URI
codes = auth.confirm_totp(user.id, "123456")     # -> 10 one-time recovery codes
auth.login("you@example.com", "…", otp="654321")      # now required
auth.disable_totp(user.id, current_password="…")
```

10 consecutive bad codes lock the second factor (`OtpLocked`); a recovery code
still works and clears the lock. `auth.disable_totp(user_id)` with no password
is the admin/support path (wire it behind your own permission check).

## Install

Not on PyPI yet — install straight from GitHub, pinned to a tag (the badge at
the top of this page always shows the latest one — check there rather than
trusting this snippet not to lag behind a release):

```sh
pip install "sessionkit @ git+https://github.com/atownsend247/bb-py-sessionkit.git@v0.2.0"
```

or as a dependency line in `pyproject.toml`:

```toml
dependencies = [
    "sessionkit @ git+https://github.com/atownsend247/bb-py-sessionkit.git@v0.2.0",
]
```

**Why a pinned tag, not a version range:** pip's `>=` / `~=` / wildcard range
syntax only works against a real package index (PyPI, or a private one) — a
`git+https://…` direct reference takes exactly one ref and nothing fuzzier.
The closest thing to "always latest" is dropping the `@<tag>` entirely (or
using `@main`), which resolves to the default branch's current tip — but then
`pip install` (and CI) silently pick up whatever's newest, including a
breaking change, with no warning and no easy rollback. Not recommended;
pin a tag and bump it deliberately (`git log`/tags above show what changed).
Real version ranges become available once/if this is published to PyPI.

## Bring your own storage

`SqliteAuthStore` is bundled and self-contained (`SqliteAuthStore.open(path)`
creates its tables on first use). To use your own database, implement
`AuthStore` (it's `runtime_checkable` — ~20 methods, see `sessionkit/store.py`)
against it and pass that to `AuthService` instead.

## CLI

```sh
sessionkit add you@example.com          # or: python -m sessionkit add …
sessionkit list
sessionkit passwd you@example.com
sessionkit delete you@example.com
sessionkit 2fa-disable you@example.com  # lockout recovery
```

`--db PATH` / `$SESSIONKIT_DB` selects the SQLite file (default `auth.db`).

## Pieces

| | |
|---|---|
| `AuthService` | all the rules; stateless; injectable `hasher`, `clock`, `session_days`, `issuer` |
| `AuthStore` | the storage Protocol |
| `SqliteAuthStore` | bundled store; `.close()` + context-manager support; safe to share across threads out of the box |
| `Argon2Hasher` / `PasswordHasher` | default hasher (argon2-cffi) + the protocol to swap it |
| `User`, `TotpEnrollment`, `TwoFactorStatus`, `LoginResult` | plain dataclasses |
| `AuthError` and subclasses | `AuthenticationError`, `OtpRequired`, `OtpLocked`, `OtpInvalid`, `UserNotFound`, `DuplicateUser`, `ValidationError` |

## Security notes

- Session tokens: `secrets.token_urlsafe(32)`; only their SHA-256 is stored.
- Recovery codes: SHA-256 of the de-hyphenated, lowercased code.
- **The TOTP secret is stored as plaintext** by `SqliteAuthStore` — same trust
  boundary as the session-hash table. Encrypt at rest yourself if you need to.
- No rate-limiting on password attempts (only on TOTP codes) — put that at
  your edge (reverse proxy / WAF / login-endpoint throttle).

## Development

```sh
pip install -e ".[dev]"
pytest
```

See [`docs/`](docs/) for more: [architecture](docs/architecture.md) (the
service/store split, data model, error mapping), [development](docs/development.md)
(testing, CI, cutting a release), [integration](docs/integration.md) (a
verified FastAPI example, bring-your-own-storage).

## License

MIT — see [LICENSE](LICENSE).
