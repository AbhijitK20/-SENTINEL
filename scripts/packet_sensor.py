"""Real-packet live sensor: tail a tcpdump text stream into the SENTINEL API.

This is the real-time path the ROADMAP describes: a container (or host) runs
``tcpdump -l -n`` against a live interface, this script consumes the line
stream, converts each packet line into a UnifiedEvent with the features the
recon/lateral detectors key on (bytes, ports, SYN/RST flags), and pushes it to
``POST /v1/events`` on a running SENTINEL API. Windows, forecasting, and
attack-type detection all happen live on the server.

Usage (inside the sensor container; see docker-compose `realtime` profile):

    tcpdump -l -n -tttt -i eth0 'ip' 2>/dev/null | \
        uv run python scripts/packet_sensor.py --api http://api:8000 --api-key $KEY

The script is streaming: lines in, HTTP batches out, no intermediate files.
Offline-first contract is preserved — this is a sensor process, not runtime
source; the API itself never fetches or listens on raw sockets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sentinel.schemas import UnifiedEvent  # noqa: E402

# tcpdump -n -l line, e.g. (with -tttt omitted, default has epoch-less timestamp)
#   14:33:08.333570 IP 10.0.0.9.45678 > 10.0.0.5.3389: Flags [S], seq 123, win 64240, length 0
#   2026-09-13 14:33:08.333570 IP0 ... (with -tttt)
# The leading timestamp is optional in the pattern so both forms parse.
LINE_RE = re.compile(
    r"^(?:\S+\s+)?(?:\S+\s+)?IP\d*\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s+Flags\s+\[(?P<flags>[^]]+)\].*?length\s+(?P<len>\d+)"
)

FLAG_MAP = {
    "S": ("syn_count", 1.0),
    "R": ("rst_count", 1.0),
    "F": ("fin_count", 1.0),
    "P": ("psh_count", 1.0),
}

BATCH_SIZE = 100
FLUSH_SECONDS = 2.0  # partial batches flush at least this often


def parse_tcpdump_line(line: str, counter: int, now: datetime | None = None) -> UnifiedEvent | None:
    """Convert one tcpdump text line into a packet UnifiedEvent.

    ``now`` is the fallback timestamp when the line does not carry one; with
    ``-tttt`` tcpdump prints wall-clock times, which are parsed directly so
    windows align to true packet time.
    """
    match = LINE_RE.match(line.strip())
    if match is None:
        return None
    flags = match.group("flags")
    overhead = len(match.group("src")) + len(match.group("dst")) + 54
    features: dict[str, float] = {
        "bytes": float(overhead + int(match.group("len"))),
        "packets": 1.0,
        "source_port": float(match.group("sport")),
        "destination_port": float(match.group("dport")),
        "ack_count": 1.0 if "." in flags or "A" in flags else 0.0,
        "retransmission": 0.0,
    }
    for token, (name, value) in FLAG_MAP.items():
        features[name] = value if token in flags else 0.0
    for required in ("syn_count", "rst_count", "fin_count", "psh_count"):
        features.setdefault(required, 0.0)
    return UnifiedEvent(
        event_id=f"tcpdump:{counter}",
        timestamp=_line_timestamp(line) or now or datetime.now(UTC),
        source_entity=match.group("src"),
        destination_entity=match.group("dst"),
        event_type="packet",
        features=features,
        source_format="syslog",
        provenance="tcpdump-live",
    )


def _line_timestamp(line: str) -> datetime | None:
    """Wall-clock timestamp from a -tttt line head, e.g. '2026-09-13 14:33:08.3'."""
    head = line.strip().split(" IP")[0]
    try:
        parsed = datetime.fromisoformat(head.replace(" ", "T", 1))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def push_events(api_url: str, api_key: str, events: list[UnifiedEvent]) -> dict:
    """POST a batch of events to the SENTINEL push engine."""
    payload = {"events": [e.model_dump(mode="json") for e in events]}
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/v1/events",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=os.environ.get("SENTINEL_API_URL", "http://api:8000"))
    parser.add_argument("--api-key", default=os.environ.get("SENTINEL_API_KEY", ""))
    parser.add_argument("--batch", type=int, default=BATCH_SIZE)
    args = parser.parse_args(argv)

    if not args.api_key:
        print("missing --api-key (or SENTINEL_API_KEY)", file=sys.stderr)
        return 2

    counter = 0
    batch: list[UnifiedEvent] = []
    last_flush = time.monotonic()

    def flush() -> None:
        nonlocal batch, last_flush
        if not batch:
            return
        result = push_events(args.api, args.api_key, batch)
        if result.get("alert_status") == "alert":
            incidents = result.get("incidents", [])
            print(
                f"ALERT: peak={result.get('peak_probability')} "
                f"incidents={[i.get('risk', {}).get('level') for i in incidents]}",
                flush=True,
            )
        batch = []
        last_flush = time.monotonic()

    for line in sys.stdin:
        event = parse_tcpdump_line(line, counter)
        if event is None:
            continue
        counter += 1
        batch.append(event)
        if len(batch) >= args.batch or (time.monotonic() - last_flush) >= FLUSH_SECONDS:
            flush()
    flush()
    print(f"pushed {counter} events", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
