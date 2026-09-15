# Architecture

## Shape

```
                     ┌────────────────────┐
  your app  ───────▶ │    AuthService     │   all the rules; no storage, no
  (web routes,       │  (service.py)      │   transport opinion; injectable
   CLI, ...)         └─────────┬──────────┘   clock / hasher / session_days
                                │
                                │ only through this Protocol
                                ▼
                     ┌────────────────────┐
                     │     AuthStore      │   ~20 methods: accounts,
                     │   (store.py)       │   two-factor, sessions
                     └─────────┬──────────┘
                                │
                 ┌──────────────┴──────────────┐
                 ▼                              ▼
      ┌────────────────────┐        ┌────────────────────────┐
      │   SqliteAuthStore  │        │  your own implementation │
      │ (sqlite_store.py,  │        │  (SQLAlchemy, Postgres,  │
      │  bundled)          │        │  an existing repo class) │
      └────────────────────┘        └────────────────────────┘
```

`AuthService` is the only thing that knows the *rules* (password length,
lockout after 10 bad TOTP codes, a code is required once 2FA is confirmed,
...). It talks to storage exclusively through the `AuthStore` Protocol — a
structural type (`typing.Protocol`, `runtime_checkable`), not a base class to
subclass. Any object with the right ~20 methods satisfies it; `SqliteAuthStore`
is the bundled implementation, but a host application with its own database
can implement the Protocol directly against its existing tables and skip
`SqliteAuthStore` entirely (this is exactly what the app sessionkit was
extracted from does — see [integration.md](integration.md#bring-your-own-storage)).

This split is the whole design: `AuthService` is 100% unit-testable against a
fake `AuthStore` with no database at all, and swapping storage is a
Protocol implementation, not a fork.

## Data model

Three logical records, whatever the storage:

- **Account** (`User` dataclass) — `id`, `email` (unique, case-insensitive),
  `name`, plus a password hash the store holds but never puts on the
  dataclass. `totp_enabled` is derived (true once a TOTP secret is
  *confirmed*, not merely started).
- **Session** — an opaque token (`secrets.token_urlsafe(32)`); only its
  SHA-256 is ever persisted, so a stolen database dump can't be replayed as
  live sessions, and revocation ("log out everywhere") is a real delete, not
  a wish. Sessions expire (`session_days`, default 30) and are checked at
  read time (`purge_expired_sessions()` is a periodic-cleanup convenience,
  not required for correctness).
- **TOTP secret + recovery codes** — the secret is base32, generated on
  `start_totp_enrollment`, and only takes effect once `confirm_totp` verifies
  a real code against it (`totp_confirmed_at` gates enforcement — a
  started-but-never-confirmed enrolment doesn't require a code at login).
  Ten recovery codes are issued on confirmation; each is hashed (SHA-256 of
  the de-hyphenated, lowercased code) and single-use. A per-account failure
  counter locks the second factor after 10 consecutive bad codes
  (`OtpLocked`) — a valid recovery code still works while locked, and clears
  the lock.

**The TOTP secret is stored as plaintext** by `SqliteAuthStore` (same trust
boundary as the session-hash table — whoever can read the DB file already has
password hashes to attack). Encrypting it at rest is a valid hardening step;
it's left to the host to add, deliberately not baked in here (it would need
key management this library has no opinion on).

## Threading

`SqliteAuthStore` shares one `sqlite3.Connection`; every method is wrapped in
`self._lock` (a `threading.Lock`), so concurrent calls are serialised rather
than racing. Because of that, `connect()` / `SqliteAuthStore.open()` default
to `check_same_thread=False` — safe here specifically *because* of the lock,
and necessary for a store that's opened once (e.g. at app startup) and then
used from a thread pool, which is how most real servers dispatch requests
(FastAPI's sync routes run in a worker thread; so does a WSGI app under most
servers). `AuthService` itself holds no mutable state, so it's inherently
thread-safe as long as its store is.

## Errors

One hierarchy, rooted at `AuthError(Exception)`, carrying **no transport
opinion** — no HTTP status, no CLI exit code baked in. A caller maps them.

| Exception | Raised when | Typical status |
|---|---|---|
| `AuthenticationError` | bad credentials; an unknown/expired/missing session | 401 |
| `OtpRequired` (`AuthenticationError`) | password correct, but 2FA is on and no code was sent | 401 |
| `OtpLocked` (`AuthenticationError`) | 10+ consecutive bad codes; even a correct TOTP is refused (a recovery code still works) | 401 |
| `OtpInvalid` (`AuthError`, **not** `AuthenticationError`) | a submitted TOTP/recovery code didn't match | 422 generally; **401 specifically at login** (see below) |
| `UserNotFound` | an id/email that doesn't exist | 404 |
| `DuplicateUser` | `create_user` with an email already registered | 409 |
| `ValidationError` | an email/password/2FA-state rule was broken (short password, "start setup first", ...) | 422 |

**`OtpInvalid` is the one to get right.** It deliberately does *not* subclass
`AuthenticationError`, so a naive `except AuthenticationError` (or an error
map keyed only on that type) won't catch it — a bad code raised from
`login()` would fall through to a generic 400/500 instead of a sensible
status. Two call sites raise it with different intent:

- `AuthService.login(..., otp=...)` — the code was wrong *during login*. This
  is an authentication failure from the caller's point of view: map it to
  **401**, the same as `OtpRequired`/`OtpLocked`, so a login form's error
  handling doesn't need a special case.
- `AuthService.confirm_totp(...)` — the code was wrong while *enrolling*
  2FA. This is closer to a form-validation failure: map it to **422**.

Both call sites raise the exact same `OtpInvalid` class — the status depends
on which endpoint is handling it, not on the exception alone. See
[integration.md](integration.md#error-mapping) for the worked example (a
generic map for every other endpoint, plus the login route's explicit
override).

## What this library deliberately doesn't do

- No web framework or ORM import, anywhere (`tests/test_isolation.py`
  enforces it in CI).
- No schema ownership beyond its own bundled `SqliteAuthStore` — a host with
  its own database keeps full control of its schema and migrations.
- No rate-limiting on password attempts, only on TOTP codes (the lockout
  counter). Login-attempt throttling belongs at the edge (reverse proxy,
  WAF, a login-endpoint-specific rate limiter) — it's a deployment concern,
  not a library one.
- No CSRF handling, no cookie-setting — `AuthService` hands back an opaque
  token string; what you do with it (a cookie, a header, a mobile app's
  secure storage) is entirely up to the integration.
