"""Watch the vulnerable app's log and push events into SENTINEL.

Tail ``access.log`` in real time; convert each syslog line to a
``UnifiedEvent`` and push it through ``POST /v1/events``.  The live
engine scores the windows, fires detectors, and surfaces incidents
via the same REST API the admin dashboard reads.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

LOG_PATH = Path("apps/vulnerable/access.log")
POLL_SECONDS = 2.0


def _read_new_lines(path: Path, offset: int) -> tuple[str, int]:
    if not path.exists():
        return "", offset
    data = path.read_bytes()
    if len(data) <= offset:
        return "", offset
    return data[offset:].decode("utf-8", errors="replace"), len(data)


def _parse_syslog_line(line: str, counter: int) -> dict | None:
    """Parse ``<ISO-8601> <host> <app> src=... dport=... method=... path=... status=...``

    Emits a *flow* event (event_type="flow") with features the 9 detectors
    key on: flow_event_count, failed_auth, rst_count, bytes, etc.  The
    credential detector uses failed_auth (number of 401/403 responses) and
    flow_event_count; the recon detector looks at rst_count and bytes.
    """
    parts = line.split()
    if len(parts) < 8 or "src=" not in line:
        return None
    try:
        ts = parts[0]
        src = next(p.split("=", 1)[1] for p in parts if p.startswith("src="))
        method = next(p.split("=", 1)[1] for p in parts if p.startswith("method="))
        path_val = next(p.split("=", 1)[1] for p in parts if p.startswith("path="))
        status_str = next(p.split("=", 1)[1] for p in parts if p.startswith("status="))
        status = int(status_str) if status_str.isdigit() else 0
    except (StopIteration, ValueError):
        return None

    is_failed = status in (401, 403, 500)

    features = {
        "bytes": float(100 + len(path_val) + len(method)),
        "packets": 1.0,
        "destination_port": 5000.0,
        "protocol": 6.0,
        "syn_count": 1.0,
        "ack_count": 1.0 if status == 200 else 0.0,
        "rst_count": 1.0 if status >= 400 else 0.0,
        "fin_count": 1.0,
        "psh_count": 1.0,
        "retransmission": 0.0,
        # Flow-level features the detectors key on:
        "flow_event_count": 1.0,
        "failed_auth": 1.0 if is_failed else 0.0,
        "duration": 0.05,
        "flow_iat_mean_ms": 50.0,
    }

    return {
        "event_id": f"http-scan:{counter}",
        "timestamp": ts,
        "source_entity": src,
        "destination_entity": "127.0.0.1",
        "event_type": "flow",
        "features": features,
        "source_format": "syslog",
        "provenance": f"sentinel-demo:{method} {path_val}",
    }


def push(api_url: str, api_key: str, events: list[dict]) -> dict:
    payload = json.dumps({"events": events})
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/v1/events",
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=os.environ.get("SENTINEL_API_URL", "http://api:8000"))
    parser.add_argument("--api-key", default=os.environ.get("SENTINEL_API_KEY", ""))
    parser.add_argument("--log", default=str(LOG_PATH))
    args = parser.parse_args(argv)

    if not args.api_key:
        print("missing --api-key (or SENTINEL_API_KEY)", file=sys.stderr)
        return 2

    path = Path(args.log)
    offset = 0
    counter = 0
    while True:
        new_lines, offset = _read_new_lines(path, offset)
        events = []
        for line in new_lines.splitlines():
            if not line.strip():
                continue
            ev = _parse_syslog_line(line, counter)
            if ev:
                events.append(ev)
                counter += 1
        if events:
            try:
                result = push(args.api, args.api_key, events)
                if result.get("alert_status") == "alert":
                    print(
                        f"ALERT peak={result['peak_probability']:.4f} "
                        f"incidents={len(result.get('incidents', []))}",
                        flush=True,
                    )
            except Exception as exc:
                print(f"push error: {exc}", file=sys.stderr)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
