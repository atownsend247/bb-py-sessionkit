from __future__ import annotations

import pytest

from sessionkit import cli


@pytest.fixture
def db(tmp_path) -> str:
    return str(tmp_path / "auth.db")


def _run(db, *args):
    cli.main(["--db", db, *args])


def test_add_list_and_delete(db, capsys, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt="": "password123")

    _run(db, "add", "alex@example.com", "--name", "Alex")
    assert "created alex@example.com" in capsys.readouterr().out

    # a second account so the first can be deleted (last-account guard)
    _run(db, "add", "sam@example.com")
    _run(db, "list")
    out = capsys.readouterr().out
    assert "alex@example.com" in out and "sam@example.com" in out

    _run(db, "delete", "alex@example.com")
    assert "deleted alex@example.com" in capsys.readouterr().out


def test_passwd_then_2fa_disable_noop(db, capsys, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt="": "password123")
    _run(db, "add", "alex@example.com")
    capsys.readouterr()

    _run(db, "passwd", "alex@example.com")
    assert "password updated" in capsys.readouterr().out

    _run(db, "2fa-disable", "alex@example.com")  # 2FA never enabled: harmless
    assert "two-factor disabled" in capsys.readouterr().out


def test_unknown_account_exits(db):
    with pytest.raises(SystemExit):
        _run(db, "delete", "nobody@example.com")


def test_bad_password_is_reported_not_raised(db, capsys, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt="": "short")
    with pytest.raises(SystemExit) as exc:
        _run(db, "add", "alex@example.com")
    assert "at least 8" in str(exc.value)
