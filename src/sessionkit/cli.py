"""Account-management CLI for a sessionkit-backed app.

    python -m sessionkit add alex@example.com --name Alex
    python -m sessionkit list
    python -m sessionkit passwd alex@example.com
    python -m sessionkit delete alex@example.com
    python -m sessionkit 2fa-disable alex@example.com   # locked out? reset it

Runs against the bundled :class:`SqliteAuthStore`; ``--db`` (or ``$SESSIONKIT_DB``,
default ``auth.db``) is the SQLite path. A host app with its own store usually
ships its own wrapper instead of this.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from .errors import AuthError
from .service import AuthService
from .sqlite_store import SqliteAuthStore


def _prompt_new_password() -> str:
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Confirm password: "):
        sys.exit("passwords do not match")
    return first


def build_parser(prog: str = "python -m sessionkit") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument(
        "--db",
        default=os.environ.get("SESSIONKIT_DB", "auth.db"),
        help="SQLite path (default: $SESSIONKIT_DB or auth.db)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", help="create an account")
    add.add_argument("email")
    add.add_argument("--name", help="display name (defaults to the email local part)")

    sub.add_parser("list", help="list accounts")

    pw = sub.add_parser("passwd", help="set an account's password")
    pw.add_argument("email")

    rm = sub.add_parser("delete", help="delete an account")
    rm.add_argument("email")

    tfa = sub.add_parser(
        "2fa-disable", help="turn off two-factor for an account (lockout recovery)"
    )
    tfa.add_argument("email")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    with SqliteAuthStore.open(args.db) as store:
        auth = AuthService(store)

        try:
            if args.command == "add":
                user = auth.create_user(args.email, _prompt_new_password(), name=args.name)
                print(f"created {user.email} (id {user.id})")

            elif args.command == "list":
                users = auth.list_users()
                if not users:
                    print("(no accounts yet)")
                for user in users:
                    print(f"{user.id:>3}  {user.email}  ({user.name})")

            elif args.command == "passwd":
                user = auth.find_user(args.email)
                if user is None:
                    sys.exit(f"no such account: {args.email}")
                auth.set_password(user.id, _prompt_new_password())
                print(f"password updated for {user.email}")

            elif args.command == "delete":
                user = auth.find_user(args.email)
                if user is None:
                    sys.exit(f"no such account: {args.email}")
                auth.delete_user(user.id)
                print(f"deleted {user.email}")

            elif args.command == "2fa-disable":
                user = auth.find_user(args.email)
                if user is None:
                    sys.exit(f"no such account: {args.email}")
                auth.disable_totp(user.id)
                print(f"two-factor disabled for {user.email}")

        except AuthError as exc:
            sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
