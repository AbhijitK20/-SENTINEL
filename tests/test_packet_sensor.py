"""Tests for scripts/packet_sensor.py — tcpdump line parsing and batching.

No network is exercised: push_events is monkeypatched; only the line -> event
contract and the stdin loop behaviour are pinned.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "packet_sensor.py"
spec = importlib.util.spec_from_file_location("packet_sensor", SCRIPT)
packet_sensor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet_sensor)  # type: ignore[union-attr]

NOW = datetime(2026, 9, 13, 14, 0, 0, tzinfo=UTC)


def test_parse_syn_probe() -> None:
    event = packet_sensor.parse_tcpdump_line(
        "IP 172.27.0.9.45678 > 172.27.0.5.3389: Flags [S], seq 123, win 64240, length 0", 0, NOW
    )
    assert event is not None
    assert event.source_entity == "172.27.0.9"
    assert event.destination_entity == "172.27.0.5"
    assert event.features["syn_count"] == 1.0
    assert event.features["rst_count"] == 0.0
    assert event.features["destination_port"] == 3389.0
    assert event.event_type == "packet"


def test_parse_timestamped_line_real_tcpdump_shape() -> None:
    # Default tcpdump (-tttt absent) prints only HH:MM:SS.frac; -tttt prints
    # full dates. Both must parse; the timestamped form carries packet time.
    line = (
        "2026-09-13 14:33:08.333570 IP 172.28.0.9.58707 > 172.28.0.3.445: "
        "Flags [S], seq 4133176724, win 1024, options [mss 1460], length 0"
    )
    event = packet_sensor.parse_tcpdump_line(line, 0, NOW)
    assert event is not None
    assert event.timestamp == datetime(2026, 9, 13, 14, 33, 8, 333570, tzinfo=UTC)
    assert event.features["syn_count"] == 1.0

    short = "14:33:08.333570 IP 172.28.0.9.58707 > 172.28.0.3.445: Flags [S], seq 1, length 0"
    event2 = packet_sensor.parse_tcpdump_line(short, 1, NOW)
    assert event2 is not None  # parses; falls back to `now` for the time
    assert event2.timestamp == NOW


def test_parse_rst_response() -> None:
    event = packet_sensor.parse_tcpdump_line(
        "IP 172.27.0.5.3389 > 172.27.0.9.45678: Flags [R.], seq 0, ack 123, win 0, length 0", 1, NOW
    )
    assert event is not None
    assert event.features["rst_count"] == 1.0
    assert event.features["ack_count"] == 1.0


def test_parse_non_ip_line_is_none() -> None:
    noise = ["reading from file eth0, link-type EN10MB", "garbage without pattern", ""]
    for line in noise:
        assert packet_sensor.parse_tcpdump_line(line, 0, NOW) is None


def test_main_pushes_batches(monkeypatch, capsys) -> None:
    pushed: list[list[dict]] = []

    def fake_push(api: str, key: str, events: list) -> dict:
        pushed.append(events)
        return {"alert_status": "below-threshold", "peak_probability": 0.1, "incidents": []}

    monkeypatch.setattr(packet_sensor, "push_events", fake_push)
    lines = [
        "2026-09-13 14:00:00.000000 IP 10.0.0.9.40000 > 10.0.0.5.445: Flags [S], seq 1, length 0",
        "tcpdump: verbose output suppressed",
        "2026-09-13 14:00:00.100000 IP 10.0.0.9.40001 > 10.0.0.6.3389: Flags [S], seq 2, length 0",
        "2026-09-13 14:00:00.200000 IP 10.0.0.9.40002 > 10.0.0.7.22: Flags [S], seq 3, length 0",
    ]
    monkeypatch.setattr("sys.stdin", iter(lines))
    code = packet_sensor.main(["--api-key", "sent_x", "--batch", "2"])
    assert code == 0
    sizes = [len(batch) for batch in pushed]
    assert sizes == [2, 1]
    assert pushed[0][0].event_id == "tcpdump:0"
    assert pushed[0][0].timestamp == datetime(2026, 9, 13, 14, 0, 0, tzinfo=UTC)


def test_main_requires_api_key(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", [])
    code = packet_sensor.main(["--api-key", ""])
    assert code == 2
