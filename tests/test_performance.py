"""Performance tests for S1-T3: ingestion and windowing speed."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trajectory.ingestion import read_flow_csv
from trajectory.schemas import UnifiedEvent
from trajectory.state_builder import build_network_states

START = datetime(2026, 1, 1, tzinfo=UTC)


def _make_events(n: int) -> list[UnifiedEvent]:
    """Generate n synthetic flow events spread over 9 hours."""
    events = []
    span = timedelta(hours=9)
    step = span / max(n, 1)
    for i in range(n):
        events.append(
            UnifiedEvent(
                event_id=f"evt-{i}",
                timestamp=START + step * i,
                source_entity=f"host-{i % 50}",
                destination_entity=f"server-{i % 20}",
                event_type="flow",
                features={"bytes": float(i % 1000), "packets": float(i % 100)},
                source_format="replay",
                provenance=f"perf:{i}",
            )
        )
    return events


@pytest.mark.performance
def test_build_network_states_200k_under_5s() -> None:
    """AC2: 200,000 events, 60s/30s windows → build_network_states < 5s."""
    events = _make_events(200_000)
    t0 = time.perf_counter()
    states = build_network_states(events, window_seconds=60, stride_seconds=30)
    elapsed = time.perf_counter() - t0
    assert len(states) > 0
    assert elapsed < 5.0, f"build_network_states took {elapsed:.2f}s (limit: 5s)"


@pytest.mark.performance
def test_read_flow_csv_200k_under_10s(tmp_path: Path) -> None:
    """AC3: 200,000-row CSV → read_flow_csv < 10s."""
    csv_path = tmp_path / "perf.csv"
    header = (
        "timestamp,source_entity,destination_entity,source_port,"
        "destination_port,protocol,bytes,packets,duration"
    )
    lines = [header]
    span = timedelta(hours=9)
    step = span / 200_000
    for i in range(200_000):
        ts = (START + step * i).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"{ts},host-{i % 50},server-{i % 20},443,80,6,{i % 1000},{i % 100},0.1")
    csv_path.write_text("\n".join(lines), encoding="utf-8")

    t0 = time.perf_counter()
    result = read_flow_csv(csv_path)
    elapsed = time.perf_counter() - t0
    assert len(result.events) == 200_000
    assert elapsed < 10.0, f"read_flow_csv took {elapsed:.2f}s (limit: 10s)"


@pytest.mark.performance
def test_state_builder_correctness_identical_output() -> None:
    """AC1: bisect-based output matches original on small input."""
    events = [
        UnifiedEvent(
            event_id="f1",
            timestamp=START,
            source_entity="a",
            destination_entity="b",
            event_type="flow",
            features={"bytes": 100.0},
            source_format="replay",
            provenance="r:f1",
        ),
        UnifiedEvent(
            event_id="f2",
            timestamp=START + timedelta(seconds=40),
            source_entity="a",
            destination_entity="b",
            event_type="flow",
            features={"bytes": 200.0},
            source_format="replay",
            provenance="r:f2",
        ),
        UnifiedEvent(
            event_id="f3",
            timestamp=START + timedelta(seconds=75),
            source_entity="c",
            destination_entity="d",
            event_type="packet",
            features={"bytes": 50.0},
            source_format="replay",
            provenance="r:f3",
        ),
    ]
    states = build_network_states(events, window_seconds=60, stride_seconds=30)
    # Windows: [0,60) has events 0s,40s. [30,90) has 40s,75s. [60,120) has 75s.
    assert len(states) == 3
    assert states[0].source_ids == ["f1", "f2"]
    assert states[0].features["bytes"] == 300.0
    assert states[1].source_ids == ["f2", "f3"]
    assert states[2].source_ids == ["f3"]
    assert states[2].features["bytes"] == 50.0
