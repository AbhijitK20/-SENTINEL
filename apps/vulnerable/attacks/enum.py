"""API enumeration attack against the demo app.

Probes API endpoints, extracts user data, and tests for information
disclosure. Generates real traffic the scanner pushes into SENTINEL,
triggering the reconnaissance and exfiltration detectors.

Usage: python -m attacks.enum [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time
from urllib import error, request

ENUM_PATHS = [
    "/api/items",
    "/admin/users.json",
    "/admin",
    "/login",
    "/search?q=admin",
    "/search?q=secret",
    "/search?q=SELECT",
    "/comments",
    "/.env",
    "/config.php",
    "/robots.txt",
    "/.git/HEAD",
    "/debug",
    "/metrics",
    "/actuator",
    "/console",
    "/swagger.json",
    "/api-docs",
    "/graphql",
]


def run(target: str, delay: float = 0.15, rounds: int = 2) -> int:
    target = target.rstrip("/")
    total = len(ENUM_PATHS) * rounds
    print(
        f"[enum] probing {target} — {len(ENUM_PATHS)} endpoints x{rounds} rounds ({total} requests)"
    )

    data_leaked = 0
    for round_idx in range(rounds):
        for path in ENUM_PATHS:
            url = f"{target}{path}"
            try:
                resp = request.urlopen(request.Request(url), timeout=5)
                code = resp.getcode()
                body = resp.read().decode(errors="replace")[:300]
            except error.HTTPError as e:
                code = e.code
                body = ""
            except Exception:
                code = 0
                body = ""

            # Check for sensitive data leakage
            has_users = "admin" in body.lower() or "username" in body.lower()
            has_secrets = "secret" in body.lower() or "password" in body.lower()
            has_json = body.strip().startswith("{") or body.strip().startswith("[")
            leaked = has_users or has_secrets

            if leaked:
                data_leaked += 1

            indicators = []
            if has_users:
                indicators.append("users")
            if has_secrets:
                indicators.append("secrets")
            if has_json:
                indicators.append("json")
            indicator_str = ",".join(indicators) if indicators else "none"

            print(
                f"  round {round_idx + 1}  path={path[:30]:30s}  "
                f"status={code}  leaked={indicator_str}"
            )
            time.sleep(delay)

    print(f"[enum] done: {total} requests, {data_leaked} endpoints leaked data")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--rounds", type=int, default=2)
    args = parser.parse_args()
    return run(args.target, delay=args.delay, rounds=args.rounds)


if __name__ == "__main__":
    raise SystemExit(main())
