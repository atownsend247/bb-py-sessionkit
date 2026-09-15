# Development

## Setup

```sh
git clone https://github.com/atownsend247/bb-py-sessionkit.git
cd bb-py-sessionkit
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Requires Python 3.13 (`requires-python = ">=3.13"` in `pyproject.toml` — this
was inherited from the app sessionkit was extracted from, not a real
technical need; don't widen it without a reason, and don't narrow it either
without checking nothing relies on a 3.13-only stdlib feature).

`hatch run test` is equivalent if you use [Hatch](https://hatch.pypa.io)
instead of a plain venv.

## Layout

```
pyproject.toml
src/sessionkit/        flat - one package, no subpackages
  __init__.py           public exports + __version__
  service.py             AuthService - all the rules
  store.py                AuthStore - the storage Protocol (runtime_checkable)
  sqlite_store.py          SqliteAuthStore - bundled reference storage
  hashing.py                PasswordHasher Protocol + Argon2Hasher
  models.py                  User / TotpEnrollment / TwoFactorStatus / LoginResult
  errors.py                   AuthError + subclasses
  cli.py / __main__.py         `python -m sessionkit` / `sessionkit` console script
tests/                  flat - one directory, mirrors the one package
  conftest.py            shared fixtures (below)
  test_service_sqlite.py  AuthService behaviour, end to end via SqliteAuthStore
  test_sqlite_store.py     SqliteAuthStore itself: CRUD, close(), threading
  test_cli.py               the account CLI
  test_isolation.py         the "no forbidden imports" guard (see below)
docs/                  this directory
.github/workflows/ci.yml
```

## Testing conventions

- `tests/conftest.py` provides: `clock` (a settable `FakeClock`), `FakeHasher`
  (fast stand-in for Argon2), `store` (a fresh `SqliteAuthStore` over
  `:memory:`), `auth` (an `AuthService` wired to both). Prefer these over
  hitting `Argon2Hasher` (slow — real Argon2 hashing) or a real clock
  (non-deterministic) in a test.
- **`tests/test_isolation.py`** parses every `src/sessionkit/*.py` file with
  `ast` and fails if any of them import `inventory`, `fastapi`, `starlette`,
  or `pydantic`. This is the thing that makes every other claim in
  [architecture.md](architecture.md#what-this-library-deliberately-doesnt-do)
  ("framework-agnostic") an enforced fact rather than a promise. Extend the
  forbidden-prefix list if a new temptation shows up; don't delete the test.
- **Real regression tests for real bugs**, not just config assertions —
  `test_sqlite_store.py` opens a store on the main thread and touches it from
  a `threading.Thread` to prove `check_same_thread=False` actually works
  cross-thread (and that `check_same_thread=True` still enforces the
  restriction when asked for), and closes stores it doesn't need open to
  prove `close()` really releases the connection (`-W error::ResourceWarning`
  turns any leak in the whole suite into a hard failure — that's the bar).
- Run the **full** suite (`pytest`) before calling a change done, not just
  the file you touched — `AuthService` is small enough that this is always
  fast (well under a second).

## Coverage

`fail_under = 90` in `[tool.coverage.report]`, source is just `sessionkit`
(`src/sessionkit/__main__.py` is the one exemption — it's a single
delegating line to `cli.main()`). `pytest --cov` enforces it locally the same
way CI does.

## CI (`.github/workflows/ci.yml`)

Three jobs:

- **`test`** — every push to `main`, every PR, every tag push: installs,
  runs `pytest` with JUnit + coverage output, writes a coverage table to the
  job summary, uploads the JUnit XML as an artifact.
- **`publish-test-results`** — turns that JUnit XML into a "Test Results"
  check run (and a PR comment, when the run was triggered by a PR), via
  `EnricoMi/publish-unit-test-result-action`.
- **`bump-readme-pin`** — **only** on a `v*` tag push, and only after `test`
  passes: checks out `main` (not the tag — the tag itself is never rewritten),
  rewrites the two pinned `git+https://…@vX.Y.Z` install snippets in
  `README.md` to the tag that was just pushed, and commits + pushes that to
  `main` if anything actually changed. This is a deliberate exception to
  "CI shouldn't auto-commit" — a tag push is an infrequent, deliberate act
  (unlike every push to `main`), so the commit doesn't create a "pull before
  your next push" surprise.

## Cutting a release

There's no PyPI package (yet) — a "release" is a git tag.

1. Make sure `pytest --cov` is green locally.
2. Bump `__version__` in `src/sessionkit/__init__.py` (semver-ish: patch for
   a backward-compatible fix, minor for a new capability, major once there's
   any reason to think about breaking changes — nothing has needed a major
   bump yet).
3. Commit that.
4. `git tag -a vX.Y.Z -m "..."` and `git push origin main && git push origin vX.Y.Z`.
5. CI re-runs the tests against the tagged commit and bumps `README.md`'s
   install snippets automatically — `git pull` afterwards to get that commit
   locally.
6. Downstream consumers (e.g. `inventory-system`) bump their own pin
   (`sessionkit @ git+https://…@vX.Y.Z`) on their own schedule — nothing here
   pushes that change to them.

See [integration.md](integration.md) for how a consumer verifies a new tag
before bumping its pin.
