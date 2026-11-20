"""Manage dashboard accounts.

    python -m dashboard.users add narz --name "Narz"   # asks for the password
    python -m dashboard.users add rod --generate        # makes and prints a random one
    python -m dashboard.users list
    python -m dashboard.users remove rod

Once any account exists, the built-in "owner" login stops working.
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets

from . import db


def generate_password() -> str:
    # three short words are easier to type during a demo than random symbols
    words = ["ilaw", "bantay", "kalye", "tanod", "susi", "pinto", "ulan", "bagyo", "araw", "gabi",
             "isla", "bundok", "dagat", "hangin", "lupa", "puno", "bato", "ilog", "tulay", "baryo"]
    return "-".join(secrets.choice(words) for _ in range(3)) + f"-{secrets.randbelow(90) + 10}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=os.environ.get("TANOD_DB", "data/tanod.db"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add")
    add.add_argument("username")
    add.add_argument("--name")
    add.add_argument("--generate", action="store_true", help="create a random password and print it")
    sub.add_parser("list")
    rm = sub.add_parser("remove")
    rm.add_argument("username")
    args = ap.parse_args(argv)

    conn = db.connect(args.db)
    if args.cmd == "add":
        if args.generate:
            pw = generate_password()
        else:
            pw = getpass.getpass(f"Password for {args.username}: ")
            if len(pw) < 8:
                raise SystemExit("Use at least 8 characters.")
            if pw != getpass.getpass("Again: "):
                raise SystemExit("Passwords do not match.")
        db.set_user(conn, args.username, pw, args.name)
        print(f"Saved account {args.username.lower()}" + (f" with password: {pw}" if args.generate else ""))
    elif args.cmd == "list":
        for u in db.list_users(conn):
            print(f"{u['username']:12s} {u['display_name']}")
    else:
        print("Removed" if db.delete_user(conn, args.username) else "No such account")


if __name__ == "__main__":
    main()
