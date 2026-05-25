"""
Generate a bcrypt hash for the admin password.

Run this once when setting up (or whenever you want to change the admin password).
Paste the resulting hash into .env as ADMIN_PASSWORD_HASH.

Usage:
    python -m scripts.make_admin_password_hash
"""

import getpass
import sys

import bcrypt


def main() -> int:
    pw1 = getpass.getpass("New admin password: ")
    if not pw1:
        print("Empty password rejected.", file=sys.stderr)
        return 1
    if len(pw1) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        return 1

    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("Passwords do not match.", file=sys.stderr)
        return 1

    hashed = bcrypt.hashpw(pw1.encode("utf-8"), bcrypt.gensalt(rounds=12))
    print()
    print("Add this line to your .env file:")
    print()
    print(f"ADMIN_PASSWORD_HASH={hashed.decode('utf-8')}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
