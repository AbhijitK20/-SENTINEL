"""Tests for scripts/flow_sensor.py — flow aggregation from tcpdump lines.

No network: push_events is monkeypatched. These tests pin the flow lifecycle
(SYN start, RST/FIN teardown, idle/max-age sweep) and the CIC-compatible
feature mapping the trained forecaster consumes.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

_spec = importlib.util.spec_from_file_location("packet_sensor", SCRIPTS / "packet_sensor.py")
packet_sensor = importlib.util.module_from_spec(_spec)
sys.modules["packet_sensor"] = packet_sensor
_spec.loader.exec_module(packet_sensor)  # type: ignore[union-attr]

_spec = importlib.util.spec_from_file_location("flow_sensor", SCRIPTS / "flow_sensor.py")
flow_sensor = importlib.util.module_from_spec(_spec)
sys.modules["flow_sensor"] = flow_sensor
_spec.loader.exec_module(flow_sensor)  # type: ignore[union-attr]

T0 = datetime(2026, 9, 13, 15, 0, 0, tzinfo=UTC)


def _pkt(
    offset: float,
    src="172.28.0.9",
    sport=40000,
    dst="172.28.0.3",
    dport=445,
    flags="S",
    length=0,
):
    return flow_sensor.PacketFields(
        timestamp=T0 + timedelta(seconds=offset),
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        protocol="tcp",
        syn="S" in flags,
        ack="." in flags or "A" in flags,
        fin="F" in flags,
        rst="R" in flags,
        psh="P" in flags,
        length=length,
        ip_overhead=54,
    )


def test_syn_rst_produces_one_flow_event() -> None:
    table = flow_sensor.FlowTable(idle_seconds=15.0, max_age_seconds=60.0)
    table.add(_pkt(0.0, flags="S"))
    table.add(_pkt(0.1, flags="S."))
    table.add(_pkt(0.2, flags="R", dport=445, sport=40000))
    events = table.sweep(T0 + timedelta(seconds=30))
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "flow"
    assert event.source_entity == "172.28.0.9"
    assert event.destination_entity == "172.28.0.3"
    assert event.features["packets"] == 3.0
    assert event.features["syn_count"] == 2.0
    assert event.features["rst_count"] == 1.0
    assert event.features["destination_port"] == 445.0
    assert event.features["protocol"] == 6.0
    assert event.features["duration"] >= 0.2


def test_two_different_ports_are_two_flows() -> None:
    table = flow_sensor.FlowTable(idle_seconds=15.0, max_age_seconds=60.0)
    # nmap-style half-open scan: pure SYN probes, each port its own flow.
    for i, port in enumerate([21, 22, 23, 80, 445, 3389]):
        table.add(_pkt(i * 0.5, dport=port, flags="S"))
    events = table.sweep(T0 + timedelta(seconds=30))
    assert len(events) == 6
    ports = sorted(e.features["destination_port"] for e in events)
    assert ports == [21.0, 22.0, 23.0, 80.0, 445.0, 3389.0]
    assert all(e.features["syn_count"] == 1.0 for e in events)
    assert all(e.features["packets"] == 1.0 for e in events)


def test_idle_sweep_flushes_long_flows() -> None:
    table = flow_sensor.FlowTable(idle_seconds=15.0, max_age_seconds=60.0)
    table.add(_pkt(0.0, flags="S"))
    assert table.sweep(T0 + timedelta(seconds=5)) == []  # still active
    events = table.sweep(T0 + timedelta(seconds=20))  # idle > 15s
    assert len(events) == 1
    assert events[0].features["packets"] == 1.0


def test_iat_mean_recorded() -> None:
    table = flow_sensor.FlowTable(idle_seconds=15.0, max_age_seconds=60.0)
    table.add(_pkt(0.0, flags="S"))
    table.add(_pkt(0.5, flags="."))
    table.add(_pkt(1.0, flags="F"))
    events = table.sweep(T0 + timedelta(seconds=30))
    assert len(events) == 1
    assert events[0].features["flow_iat_mean_ms"] == 500.0  # mean of 500,500


def test_main_streams_flows(monkeypatch) -> None:
    pushed: list[list] = []

    def fake_push(api: str, key: str, events: list) -> dict:
        pushed.append(events)
        return {"alert_status": "below-threshold", "peak_probability": 0.1, "incidents": []}

    monkeypatch.setattr(flow_sensor, "push_events", fake_push)
    lines = [
        "2026-09-13 15:00:00.000000 IP 172.28.0.9.40001 > 172.28.0.3.445: "
        "Flags [S], seq 1, length 0",
        "2026-09-13 15:00:00.500000 IP 172.28.0.3.445 > 172.28.0.9.40001: "
        "Flags [S.], seq 2, ack 1, length 0",
        "2026-09-13 15:00:01.000000 IP 172.28.0.9.40001 > 172.28.0.3.445: "
        "Flags [R], seq 3, length 0",
        "2026-09-13 15:00:02.000000 IP 172.28.0.9.40002 > 172.28.0.3.3389: "
        "Flags [S], seq 4, length 0",
    ]
    monkeypatch.setattr("sys.stdin", iter(lines))
    code = flow_sensor.main(["--api-key", "sent_x"])
    assert code == 0
    flat = [e for batch in pushed for e in batch]
    # 4 packets -> 2 flows (445 flow torn down by RST; 3389 pure SYN flushed at EOF)
    assert len(flat) == 2
    assert all(e.event_type == "flow" for e in flat)
    assert {e.features["packets"] for e in flat} == {3.0, 1.0}


def test_main_requires_api_key(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", iter([]))
    assert flow_sensor.main(["--api-key", ""]) == 2
