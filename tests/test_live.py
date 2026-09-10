"""Tests for the live detection engine and its event sources."""

from __future__ import annotations

import json
import queue
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.live import (
    CsvReplaySource,
    EventReplaySource,
    JsonlSensorSource,
    LiveEngine,
)
from trajectory.predict import DECISION_THRESHOLD, artifacts_from_runs, load_artifacts
from trajectory.schemas import UnifiedEvent
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"lv{i}" for i in range(5)]
START = datetime(2026, 1, 1, tzinfo=UTC)


def _loaded(tmp_path: Path):
    labelled = generate_labelled_states(SCENARIOS, seed=11, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=11)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=11,
    )
    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    return load_artifacts(baseline_dir)


def _event(offset_seconds: float, index: int, **features) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"t{index}",
        timestamp=START + timedelta(seconds=offset_seconds),
        source_entity="10.0.0.1",
        destination_entity="10.0.0.2",
        event_type="flow",
        features={"bytes": 100.0, **features},
        source_format="replay",
        provenance="test",
    )


def _make_engine(loaded) -> LiveEngine:
    return LiveEngine(
        loaded,
        source=JsonlSensorSource(Path("/tmp/unused.jsonl")),
        window_seconds=60,
        stride_seconds=30,
        history=2,
        max_history=3,
    )


def test_windows_emit_on_stride_boundaries(tmp_path: Path) -> None:
    engine = _make_engine(_loaded(tmp_path))
    # Two events inside the first stride window [0, 30).
    engine.ingest(_event(0.0, 1))
    engine.ingest(_event(10.0, 2))
    status = engine.poll()
    assert status.windows_emitted == 0  # boundary not crossed yet

    # Crossing t=30 closes the first window; t=65 closes the second.
    engine.ingest(_event(31.0, 3))
    status = engine.poll()
    assert status.windows_emitted == 1
    assert status.history[0].event_count == 2
    assert status.history[0].window_start == START

    engine.ingest(_event(65.0, 4))
    status = engine.poll()
    assert status.windows_emitted == 2
    assert status.history[1].event_count == 1  # only t=31 in [30, 60)


def test_empty_windows_are_skipped_not_fabricated(tmp_path: Path) -> None:
    engine = _make_engine(_loaded(tmp_path))
    engine.ingest(_event(0.0, 1))
    # Jump 10 minutes ahead: many empty stride windows in between.
    engine.ingest(_event(600.0, 2))
    status = engine.poll()
    assert status.windows_emitted == 1  # only the window containing t=600
    assert status.history[0].event_count == 1


def test_forecast_comes_from_real_artifacts(tmp_path: Path) -> None:
    engine = _make_engine(_loaded(tmp_path))
    for index in range(4):
        engine.ingest(_event(float(index) * 10.0, index))
    status = engine.poll()
    latest = status.history[-1]
    assert 0.0 <= latest.probability <= 1.0
    assert latest.threshold == status.threshold
    assert latest.stage  # stage mapping always yields a stage or Unknown


def test_fast_attack_shaped_windows_cross_threshold(tmp_path: Path) -> None:
    """The local speed-2 attack path must produce a visible alert spike."""
    labelled = generate_labelled_states(
        [f"attack-{index}" for index in range(1, 7)],
        seed=42,
        window_seconds=60,
        stride_seconds=30,
    )
    samples = build_sequence_samples(labelled, sequence_length=8, horizon=5)
    manifest = make_split_manifest([f"attack-{index}" for index in range(1, 7)], seed=42)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=42,
    )

    attack_events = [
        _event(0.0, 1, bytes=64.0, packets=6.0),
        *[
            _event(
                10.0 + (index % 20) * 0.05,
                index,
                bytes=0.0,
                packets=1.0,
                syn_count=1.0,
                rst_count=1.0,
            )
            for index in range(2, 252)
        ],
        *[
            _event(
                35.0 + (index % 25) * 0.05,
                index,
                bytes=48000.0,
                packets=40.0,
                syn_count=1.0,
                ack_count=39.0,
            )
            for index in range(252, 285)
        ],
    ]
    source = EventReplaySource(attack_events, speed=1_000_000)
    engine = LiveEngine(
        artifacts_from_runs(run),
        source=source,
        window_seconds=30,
        stride_seconds=15,
        history=120,
        threshold=DECISION_THRESHOLD,
    )
    engine.start()
    for _ in range(100):
        status = engine.poll()
        if not status.running:
            break
        time.sleep(0.01)
    assert status.windows_emitted >= 1
    assert max(window.probability for window in status.history) >= DECISION_THRESHOLD


def test_history_is_bounded(tmp_path: Path) -> None:
    engine = _make_engine(_loaded(tmp_path))
    for index in range(0, 30):
        engine.ingest(_event(float(index) * 10.0, index))
    status = engine.poll()
    assert status.windows_emitted == 3  # max_history
    assert status.events_seen == 30


def test_invalid_configuration_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="stride"):
        LiveEngine(
            _loaded(tmp_path),
            source=JsonlSensorSource(Path("/tmp/unused.jsonl")),
            window_seconds=30,
            stride_seconds=60,
        )


def test_event_replay_source_streams_in_memory_events() -> None:
    source = EventReplaySource([_event(0.0, 1), _event(1.0, 2)], speed=1_000_000)
    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    source.run(events, stop)

    first = events.get_nowait()
    second = events.get_nowait()
    assert first.event_id == "t1"
    assert second.event_id == "t2"


def _write_jsonl(path: Path, count: int) -> None:
    lines = [
        json.dumps(
            {
                "timestamp": (START + timedelta(seconds=index)).isoformat(),
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "event_type": "flow",
                "features": {"bytes": 50.0},
            }
        )
        for index in range(count)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_jsonl_sensor_source_streams_events(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(path, 3)
    source = JsonlSensorSource(path, poll_seconds=0.05)
    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    worker = threading.Thread(target=source.run, args=(events, stop), daemon=True)
    worker.start()

    from trajectory.live import _SENTINEL

    collected = []
    while len(collected) < 3:
        item = events.get(timeout=5.0)
        if item is not _SENTINEL:
            collected.append(item)
    stop.set()  # tailing sources wait for more lines until stopped
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    item = events.get(timeout=2.0)
    assert item is _SENTINEL  # end-of-stream marker after stop

    assert len(collected) == 3
    assert collected[0].features["bytes"] == 50.0
    assert collected[0].timestamp == START


def test_jsonl_sensor_source_can_finish_uploaded_replay(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    _write_jsonl(path, 2)
    source = JsonlSensorSource(path, follow=False)
    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    source.run(events, stop)

    collected = []
    from trajectory.live import _SENTINEL

    while True:
        item = events.get_nowait()
        if item is _SENTINEL:
            break
        collected.append(item)
    assert len(collected) == 2


COLUMNS = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Flow IAT Mean",
    "Label",
]


def test_csv_replay_source_ordered_and_terminated(tmp_path: Path) -> None:
    path = tmp_path / "flows.csv"
    rows = [
        {
            "Flow ID": f"f{i}",
            "Source IP": "10.0.0.1",
            "Destination IP": "10.0.0.2",
            "Source Port": "40000",
            "Destination Port": "80",
            "Protocol": "6",
            "Timestamp": f"01/07/2017 0{i}:00:00",
            "Flow Duration": "1000",
            "Total Fwd Packet": "4",
            "Total Bwd packets": "4",
            "Total Length of Fwd Packet": "200",
            "Total Length of Bwd Packet": "300",
            "FIN Flag Count": "1",
            "SYN Flag Count": "1",
            "RST Flag Count": "0",
            "PSH Flag Count": "1",
            "ACK Flag Count": "3",
            "Flow IAT Mean": "10",
            "Label": "BENIGN",
        }
        for i in range(3)
    ]
    import csv as _csv

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = _csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    source = CsvReplaySource(path, speed=1e12)  # instant replay
    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    source.run(events, stop)
    collected = []
    while True:
        item = events.get(timeout=2.0)
        from trajectory.live import _SENTINEL

        if item is _SENTINEL:
            break
        collected.append(item)
    assert len(collected) == 3
    timestamps = [event.timestamp for event in collected]
    assert timestamps == sorted(timestamps)
