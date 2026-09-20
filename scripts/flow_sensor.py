"""Real-flow live sensor: aggregate a tcpdump stream into flow events.

Companion to ``packet_sensor.py``. Instead of pushing every packet as its own
event, this sensor maintains a 5-tuple flow table (src, sport, dst, dport,
proto) and emits ONE ``flow`` UnifiedEvent per completed flow — the same
event shape (``event_type="flow"``) the trained forecaster was fit on
(CIC-IDS2017 flow records), so the model scores the realtime path
in-distribution instead of only the rule-based detectors.

Flow lifecycle (classic NetFlow semantics, simplified):
- TCP:  a SYN starts (or restarts) a flow; RST or FIN tears it down.
- UDP:  the first packet starts a flow; only the idle timeout ends it.
- Any flow flushes when it exceeds ``--max-age`` seconds of lifetime or the
  main loop notices it idle for longer than ``--idle`` seconds.
- Features per flow: total bytes, packets, duration, per-flag counts,
  mean inter-arrival time in ms — mirroring the CICFlowMeter columns the
  baseline consumes (see trajectory/cic_ids2017.py).

Usage:

    tcpdump -l -n -tttt -i eth0 ip 2>/dev/null | \
        uv run python scripts/flow_sensor.py --api http://api:8000 --api-key $KEY

Offline-first contract preserved: this is a sensor process, not runtime
source; the API never listens on raw sockets or fetches URLs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sentinel.schemas import UnifiedEvent  # noqa: E402

BATCH_SIZE = 100
FLUSH_SECONDS = 2.0
DEFAULT_IDLE_SECONDS = 15.0
DEFAULT_MAX_AGE_SECONDS = 60.0


@dataclass
class PacketFields:
    """One parsed tcpdump line (protocol-agnostic transport fields)."""

    timestamp: datetime
    src: str
    sport: int
    dst: str
    dport: int
    protocol: str  # "tcp" | "udp"
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    length: int = 0
    ip_overhead: int = 54


@dataclass
class ActiveFlow:
    """Accumulated state for one in-progress 5-tuple flow."""

    key: tuple[str, int, str, int, str]
    start: datetime
    last: datetime
    bytes: int = 0
    packets: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    iat_total_ms: float = 0.0
    iat_samples: int = 0
    event_index: int = 0

    def absorb(self, pkt: PacketFields) -> None:
        self.last = pkt.timestamp
        self.bytes += pkt.ip_overhead + pkt.length
        self.packets += 1
        self.syn_count += int(pkt.syn)
        self.ack_count += int(pkt.ack)
        self.fin_count += int(pkt.fin)
        self.rst_count += int(pkt.rst)
        self.psh_count += int(pkt.psh)

    def to_event(self) -> UnifiedEvent:
        duration = max(0.0, (self.last - self.start).total_seconds())
        iat_mean_ms = self.iat_total_ms / self.iat_samples if self.iat_samples else 0.0
        src, sport, dst, dport, _proto = self.key
        return UnifiedEvent(
            event_id=f"flow-sensor:{self.event_index}",
            timestamp=self.start,
            source_entity=src,
            destination_entity=dst,
            event_type="flow",
            features={
                "source_port": float(sport),
                "destination_port": float(dport),
                "bytes": float(self.bytes),
                "packets": float(self.packets),
                "duration": duration,
                "flow_iat_mean_ms": iat_mean_ms,
                "syn_count": float(self.syn_count),
                "ack_count": float(self.ack_count),
                "fin_count": float(self.fin_count),
                "rst_count": float(self.rst_count),
                "psh_count": float(self.psh_count),
                "protocol": 6.0 if self.key[4] == "tcp" else 17.0,
            },
            source_format="replay",
            provenance="flow-sensor-live",
        )


def parse_packet_fields(line: str) -> PacketFields | None:
    """Parse one tcpdump -n -tttt line into transport fields; None on noise."""
    from packet_sensor import LINE_RE  # sibling script shares the line format

    match = LINE_RE.match(line.strip())
    if match is None:
        return None
    flags = match.group("flags")
    timestamp = _line_timestamp(line) or datetime.now(UTC)
    return PacketFields(
        timestamp=timestamp,
        src=match.group("src"),
        sport=int(match.group("sport")),
        dst=match.group("dst"),
        dport=int(match.group("dport")),
        protocol="tcp",
        syn="S" in flags,
        ack="." in flags or "A" in flags,
        fin="F" in flags,
        rst="R" in flags,
        psh="P" in flags,
        length=int(match.group("len")),
        ip_overhead=len(match.group("src")) + len(match.group("dst")) + 54,
    )


def _line_timestamp(line: str) -> datetime | None:
    head = line.strip().split(" IP")[0]
    try:
        parsed = datetime.fromisoformat(head.replace(" ", "T", 1))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


class FlowTable:
    """In-memory flow table keyed by 5-tuple; emits flow events on teardown."""

    def __init__(self, *, idle_seconds: float, max_age_seconds: float) -> None:
        self.idle_seconds = idle_seconds
        self.max_age_seconds = max_age_seconds
        self.flows: dict[tuple[str, int, str, int, str], ActiveFlow] = {}
        self.completed: list[UnifiedEvent] = []
        self._counter = 0

    def _next_index(self) -> int:
        self._counter += 1
        return self._counter

    def add(self, pkt: PacketFields) -> None:
        key = (pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.protocol)
        reverse = (pkt.dst, pkt.dport, pkt.src, pkt.sport, pkt.protocol)
        flow = self.flows.get(key) or self.flows.get(reverse)
        if flow is None or (pkt.syn and not pkt.ack):
            # A fresh SYN (without ACK) starts a new flow even if an old one
            # lingers: half-open scans re-emit pure SYNs. The reply direction
            # (SYN-ACK) folds into the same bidirectional flow, matching the
            # CICFlowMeter Fwd+Bwd semantics the model was trained on.
            if flow is not None:
                self._complete(flow.key)
            flow = ActiveFlow(
                key=key, start=pkt.timestamp, last=pkt.timestamp, event_index=self._next_index()
            )
            self.flows[key] = flow
        previous = flow.last
        flow.absorb(pkt)
        if flow.packets > 1:
            flow.iat_total_ms += (pkt.timestamp - previous).total_seconds() * 1000.0
            flow.iat_samples += 1
        if pkt.rst or pkt.fin:
            self._complete(flow.key)

    def _complete(self, key: tuple[str, int, str, int, str]) -> None:
        flow = self.flows.pop(key, None)
        if flow is not None and flow.packets > 0:
            self.completed.append(flow.to_event())

    def sweep(self, now: datetime) -> list[UnifiedEvent]:
        """Flush flows idle beyond ``idle_seconds`` or older than ``max_age_seconds``."""
        for key, flow in list(self.flows.items()):
            idle = (now - flow.last).total_seconds()
            age = (now - flow.start).total_seconds()
            if idle > self.idle_seconds or age > self.max_age_seconds:
                self._complete(key)
        events, self.completed = self.completed, []
        return events


def push_events(api_url: str, api_key: str, events: list[UnifiedEvent]) -> dict:
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
    parser.add_argument("--idle", type=float, default=DEFAULT_IDLE_SECONDS)
    parser.add_argument("--max-age", type=float, default=DEFAULT_MAX_AGE_SECONDS)
    args = parser.parse_args(argv)

    if not args.api_key:
        print("missing --api-key (or SENTINEL_API_KEY)", file=sys.stderr)
        return 2

    table = FlowTable(idle_seconds=args.idle, max_age_seconds=args.max_age)
    batch: list[UnifiedEvent] = []
    flows_pushed = 0
    packets_seen = 0
    last_flush = time.monotonic()

    def flush() -> None:
        nonlocal batch, last_flush, flows_pushed
        if not batch:
            return
        result = push_events(args.api, args.api_key, batch)
        flows_pushed += len(batch)
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
        pkt = parse_packet_fields(line)
        if pkt is None:
            continue
        packets_seen += 1
        table.add(pkt)
        # Periodic sweep converts idle/aged flows into events.
        if time.monotonic() - last_flush >= FLUSH_SECONDS:
            batch.extend(table.sweep(pkt.timestamp))
            if len(batch) >= args.batch:
                flush()
            else:
                last_flush = time.monotonic()
    batch.extend(table.sweep(datetime.now(UTC)))
    flush()
    print(f"aggregated {packets_seen} packets into {flows_pushed} flow events", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
