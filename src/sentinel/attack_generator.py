"""Canonical attack event generator for SENTINEL live detection.

Generates telemetry events in the JSONL wire format consumed by
``JsonlSensorSource``. Each attack scenario produces events with
realistic feature patterns that the existing stage mapping rules
and forecast model can interpret.

This module replaces the disconnected subprocess-based attack scripts
with an in-process event generator that writes directly to
``events.jsonl``.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

# Default event output path — matches attack_demo.py and JsonlSensorSource.
DEFAULT_EVENTS_PATH = (
    Path(__file__).resolve().parent.parent.parent / "reports" / "live" / "events.jsonl"
)

# Internal hosts matching the synthetic generator conventions.
INTERNAL_HOSTS = [f"host-{i:02d}" for i in range(1, 9)]
SERVERS = ["auth-service", "server-03", "file-server", "web-proxy"]


def _write_event(
    handle,
    src: str,
    dst: str,
    features: dict[str, float],
    event_type: str = "flow",
    kind: str = "connection",
) -> None:
    """Write a single canonical event to an open file handle."""
    line = json.dumps(
        {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "src": src,
            "dst": dst,
            "event_type": event_type,
            "kind": kind,
            "features": features,
        }
    )
    handle.write(line + "\n")
    handle.flush()


def _write_events(path: Path, events: list[dict]) -> None:
    """Write a batch of event dicts to the JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for evt in events:
            _write_event(
                handle,
                evt["src"],
                evt["dst"],
                evt["features"],
                evt.get("event_type", "flow"),
                evt.get("kind", "connection"),
            )


def generate_recon_events(count: int = 30) -> list[dict]:
    """Generate reconnaissance-phase events: SYN/RST probes to many ports."""
    events = []
    attacker = INTERNAL_HOSTS[0]
    for i in range(count):
        target = SERVERS[i % len(SERVERS)]
        dport = float(22 + (i * 7) % 500)
        events.append(
            {
                "src": attacker,
                "dst": target,
                "event_type": "flow",
                "kind": "reconnaissance",
                "features": {
                    "destination_port": dport,
                    "bytes": float(60 + (i % 10) * 4),
                    "packets": 2.0,
                    "syn_count": 1.0,
                    "ack_count": 0.0,
                    "rst_count": 1.0,
                    "fin_count": 0.0,
                    "failed_auth": 0.0,
                    "retransmission": 0.0,
                },
            }
        )
    return events


def generate_brute_force_events(count: int = 25) -> list[dict]:
    """Generate brute-force authentication attack events."""
    events = []
    attacker = INTERNAL_HOSTS[0]
    for i in range(count):
        target = "auth-service"
        events.append(
            {
                "src": attacker,
                "dst": target,
                "event_type": "authentication",
                "kind": "brute_force",
                "features": {
                    "destination_port": 22.0,
                    "bytes": float(120 + (i % 5) * 20),
                    "packets": 4.0,
                    "syn_count": 1.0,
                    "ack_count": 1.0,
                    "rst_count": 0.0,
                    "fin_count": 1.0,
                    "failed_auth": 1.0,
                    "retransmission": 0.0,
                },
            }
        )
    return events


def generate_sqli_events(count: int = 20) -> list[dict]:
    """Generate SQL injection web attack events."""
    events = []
    attacker = INTERNAL_HOSTS[1]
    for i in range(count):
        target = "web-proxy"
        events.append(
            {
                "src": attacker,
                "dst": target,
                "event_type": "flow",
                "kind": "web_attack",
                "features": {
                    "destination_port": 80.0,
                    "bytes": float(200 + (i % 4) * 50),
                    "packets": 6.0,
                    "syn_count": 1.0,
                    "ack_count": 2.0,
                    "rst_count": 0.0,
                    "fin_count": 1.0,
                    "failed_auth": 0.0,
                    "retransmission": 0.0,
                },
            }
        )
    return events


def generate_scan_events(count: int = 40) -> list[dict]:
    """Generate port scan events: many short connections to varied ports."""
    events = []
    attacker = INTERNAL_HOSTS[0]
    for i in range(count):
        target = SERVERS[i % len(SERVERS)]
        dport = float((i * 13 + 1) % 1024)
        events.append(
            {
                "src": attacker,
                "dst": target,
                "event_type": "flow",
                "kind": "scan",
                "features": {
                    "destination_port": dport,
                    "bytes": 40.0,
                    "packets": 1.0,
                    "syn_count": 1.0,
                    "ack_count": 0.0,
                    "rst_count": 1.0,
                    "fin_count": 0.0,
                    "failed_auth": 0.0,
                    "retransmission": 0.0,
                },
            }
        )
    return events


# Attack type -> generator mapping.
ATTACK_GENERATORS: dict[str, callable] = {
    "brute_force": generate_brute_force_events,
    "sqli": generate_sqli_events,
    "scan": generate_scan_events,
    "recon": generate_recon_events,
}


def emit_attack(
    attack_type: str,
    events_path: Path | None = None,
    count: int | None = None,
) -> Path:
    """Generate attack events and write them to the JSONL file.

    Returns the path to the events file.
    """
    path = events_path or DEFAULT_EVENTS_PATH
    generator = ATTACK_GENERATORS.get(attack_type)
    if generator is None:
        raise ValueError(f"Unknown attack type: {attack_type!r}. Valid: {list(ATTACK_GENERATORS)}")
    kwargs = {}
    if count is not None:
        kwargs["count"] = count
    events = generator(**kwargs)
    _write_events(path, events)
    return path


def emit_benign_chatter(count: int = 10) -> list[dict]:
    """Generate normal background traffic events."""
    events = []
    for i in range(count):
        src = INTERNAL_HOSTS[i % len(INTERNAL_HOSTS)]
        dst = SERVERS[i % len(SERVERS)]
        events.append(
            {
                "src": src,
                "dst": dst,
                "event_type": "flow",
                "kind": "connection",
                "features": {
                    "destination_port": [443.0, 80.0, 53.0, 8443.0][i % 4],
                    "bytes": float(400 + (i % 6) * 300),
                    "packets": float(3 + (i % 4)),
                    "syn_count": 1.0,
                    "ack_count": 1.0,
                    "rst_count": 0.0,
                    "fin_count": 1.0,
                    "failed_auth": 0.0,
                    "retransmission": 0.0,
                },
            }
        )
    return events


def emit_full_attack_sequence(
    events_path: Path | None = None,
    speed: float = 1.0,
    stop: threading.Event | None = None,
) -> Path:
    """Generate a complete attack sequence (benign -> recon -> brute force -> lateral).

    Events are written with small delays between them to simulate real-time
    traffic. The ``speed`` multiplier controls how fast events are emitted
    (higher = faster). The ``stop`` event can be used to abort early.

    Returns the path to the events file.
    """
    path = events_path or DEFAULT_EVENTS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    stop_evt = stop or threading.Event()
    delay = 0.05 / max(speed, 0.1)

    with path.open("a", encoding="utf-8") as handle:
        # Phase 1: benign chatter
        for evt in emit_benign_chatter(15):
            if stop_evt.is_set():
                break
            etype = evt.get("event_type", "flow")
            ekind = evt.get("kind", "connection")
            _write_event(handle, evt["src"], evt["dst"], evt["features"], etype, ekind)
            time.sleep(delay)

        # Phase 2: reconnaissance
        for evt in generate_recon_events(25):
            if stop_evt.is_set():
                break
            etype = evt.get("event_type", "flow")
            ekind = evt.get("kind", "connection")
            _write_event(handle, evt["src"], evt["dst"], evt["features"], etype, ekind)
            time.sleep(delay)

        # Phase 3: brute force
        for evt in generate_brute_force_events(20):
            if stop_evt.is_set():
                break
            etype = evt.get("event_type", "flow")
            ekind = evt.get("kind", "connection")
            _write_event(handle, evt["src"], evt["dst"], evt["features"], etype, ekind)
            time.sleep(delay)

        # Phase 4: lateral movement (large transfers)
        for i in range(15):
            if stop_evt.is_set():
                break
            _write_event(
                handle,
                INTERNAL_HOSTS[0],
                "file-server",
                {
                    "destination_port": 445.0,
                    "bytes": float(30000 + i * 5000),
                    "packets": float(20 + i * 3),
                    "syn_count": 1.0,
                    "ack_count": 2.0,
                    "rst_count": 0.0,
                    "fin_count": 1.0,
                    "failed_auth": 0.0,
                    "retransmission": 0.0,
                },
                "flow",
                "lateral_movement",
            )
            time.sleep(delay)

    return path
