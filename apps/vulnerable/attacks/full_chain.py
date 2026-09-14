"""Combined attack chain against the demo app.

Runs multiple attack types in sequence to simulate a real-world
attack chain: reconnaissance → credential abuse → data exfiltration.
Generates diverse traffic patterns for SENTINEL detection.

Usage: python -m attacks.full_chain [--target http://demo-app:5000]
"""

from __future__ import annotations

import argparse
import time

from attacks import brute_force, enum, scan, sqli, traversal, xss


def run(target: str, delay: float = 0.1, rounds: int = 1) -> int:
    target = target.rstrip("/")
    print(f"[full-chain] starting combined attack chain against {target}")
    print("=" * 60)

    # Phase 1: Reconnaissance
    print("\n[Phase 1] Reconnaissance — port scanning + API enumeration")
    print("-" * 60)
    scan.run(target, delay=delay, rounds=1)
    enum.run(target, delay=delay, rounds=1)

    time.sleep(1)

    # Phase 2: Exploitation
    print("\n[Phase 2] Exploitation — SQLi + XSS + directory traversal")
    print("-" * 60)
    sqli.run(target, delay=delay, max_rounds=1)
    xss.run(target, delay=delay, rounds=1)
    traversal.run(target, delay=delay, rounds=1)

    time.sleep(1)

    # Phase 3: Credential Abuse
    print("\n[Phase 3] Credential Abuse — brute force + credential stuffing")
    print("-" * 60)
    brute_force.run(target, delay=delay, max_attempts=10)

    print("\n" + "=" * 60)
    print("[full-chain] attack chain complete")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--rounds", type=int, default=1)
    args = parser.parse_args()
    return run(args.target, delay=args.delay, rounds=args.rounds)


if __name__ == "__main__":
    raise SystemExit(main())
