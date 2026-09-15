# CLAUDE.md

Accounts, opaque server-side sessions, and opt-in TOTP two-factor auth with
one-time recovery codes. Framework-agnostic Python library — no web framework,
no ORM. Extracted from a house-move inventory app (`inventory-system`); still
used there via `AuthStore`, but this repo has no knowledge of that app.

## Where things are

- `src/sessionkit/` — flat, one package, no subpackages:
  - `service.py` — `AuthService`, all the rules. Stateless-ish; takes an
    injected `store` (`AuthStore`), `hasher`, `clock`, `session_days`, `issuer`.
  - `store.py` — `AuthStore`, the storage `Protocol` (`runtime_checkable`) the
    service depends on. Anything with these ~20 methods works.
  - `sqlite_store.py` — `SqliteAuthStore`, the bundled reference storage
    (`users` / `sessions` / `recovery_codes` tables, `ensure_schema()`).
  - `hashing.py` — `PasswordHasher` Protocol + `Argon2Hasher` default.
  - `models.py` — `User`, `TotpEnrollment`, `TwoFactorStatus`, `LoginResult`
    dataclasses.
  - `errors.py` — `AuthError` base + `AuthenticationError`, `OtpRequired`,
    `OtpLocked`, `OtpInvalid`, `UserNotFound`, `DuplicateUser`,
    `ValidationError`. None of these carry an HTTP status; a caller maps them.
  - `cli.py` / `__main__.py` — `python -m sessionkit` / `sessionkit` console
    script: `add` / `list` / `passwd` / `delete` / `2fa-disable`.
- `tests/` — one flat directory (one package, no need to mirror subpackages).
  `conftest.py` has `clock` (`FakeClock`), `FakeHasher`, `store`
  (`SqliteAuthStore` over `:memory:`), `auth` (`AuthService` wired to both).

## Commands

```sh
pip install -e ".[dev]"
pytest                 # or: hatch run test
pytest --cov           # coverage; fail_under = 90 in pyproject.toml
python -m sessionkit add you@example.com   # or: sessionkit add …
```

## Architecture rules (don't violate)

- **No imports of a web framework, an ORM, or any application this library
  happens to be used from.** `tests/test_isolation.py` parses every source
  file and fails CI if one imports `inventory`, `fastapi`, `starlette`, or
  `pydantic` — extend that list rather than deleting the test if a new
  temptation shows up.
- **Storage only through `AuthStore`.** `AuthService` never touches SQL (or
  any storage API) directly; `SqliteAuthStore` is persistence only, no rules.
  A host application can implement `AuthStore` against its own database
  instead of using `SqliteAuthStore` — that's the whole point of the split.
- **`clock` and `hasher` are always injectable**, defaulting to the real
  clock / `Argon2Hasher`. Never call `datetime.now()` directly inside
  `AuthService`; always `self._clock()`.
- **Errors carry no transport opinion.** `AuthError` subclasses are plain
  Python exceptions; mapping them to HTTP status codes (or CLI exit codes) is
  entirely the caller's job. Don't import `fastapi.HTTPException` or similar
  here even for convenience.

## Conventions

- `SqliteAuthStore` owns a real `sqlite3.Connection` — always `.close()` it (or
  use it as a context manager: `with SqliteAuthStore.open(path) as store:`)
  when you're done with it. `AuthService` never closes its store — construct
  and tear down the store where you constructed it, not inside the service.
  (v0.1.0 had no `close()` at all — a caller had no clean way to release the
  connection short of reaching into the private `_conn`; fixed in v0.1.1.)
- Session tokens: `secrets.token_urlsafe(32)`; only the SHA-256 is ever
  persisted (`_token_hash`). Same idea for recovery codes (SHA-256 of the
  de-hyphenated, lowercased code).
- Timestamps: timezone-aware UTC throughout.
- 10 consecutive bad TOTP codes lock the second factor (`OtpLocked`); a valid
  recovery code still logs in and clears the lock. `disable_totp(user_id)`
  with no `current_password` is the "admin/support resets a lockout" path —
  callers should gate that behind their own permission check, it isn't gated
  here.

## Gotchas

- **The TOTP secret is stored as plaintext** by `SqliteAuthStore` (same trust
  boundary as the session-hash table). Encrypting it at rest is left to the
  host; if you add that, keep it opt-in / pluggable rather than baked in.
- No rate-limiting on password attempts, only on TOTP codes. That's a
  deliberate scope decision, not an oversight — put login-attempt throttling
  at the edge (reverse proxy / WAF) rather than in this library.
- `requires-python = ">=3.13"` in `pyproject.toml` — don't widen it to support
  an older version without a reason; nothing here needs it, it's just what the
  original host app was pinned to.
- Published as source on GitHub (`atownsend247/bb-py-sessionkit`, MIT), tagged
  releases (`v0.1.0`, ...) — **not** on PyPI. Consumers pin
  `sessionkit @ git+https://github.com/atownsend247/bb-py-sessionkit.git@<tag>`.
  Bump `__version__` in `src/sessionkit/__init__.py` and tag to cut a release;
  there's no CI workflow yet, so run `pytest --cov` locally before tagging.
