"""Tests for the Phase 3 syslog tailing source feeding the live engine."""

from __future__ import annotations

import queue
import threading
from pathlib import Path

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.live import LiveEngine, SyslogTailSource
from trajectory.predict import DECISION_THRESHOLD, load_artifacts
from trajectory.schemas import UnifiedEvent
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest
from trajectory.telemetry import parse_syslog_line

SCENARIOS = [f"sl{i}" for i in range(5)]


def _loaded(tmp_path: Path):
    """Train the same tiny deterministic baseline the live-engine tests use."""
    labelled = generate_labelled_states(SCENARIOS, seed=13, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=13)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=13,
    )
    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    return load_artifacts(baseline_dir)


BENIGN = "2026-01-01T00:00:{sec:02d}+00:00 host-01 flowd src=host-01 dst=server-03 bytes=2000"
# t=61s flush event (minute 1): closes the [60, 90) stride window.
FLUSH = "2026-01-01T00:01:01+00:00 host-01 flowd src=host-01 dst=server-03 bytes=2000"
AUTH_FAILURE = (
    "2026-01-01T00:00:{sec:02d}+00:00 host-01 authd src=10.0.0.9 dst=auth-service "
    "failed_auth=yes bytes=300"
)
SCAN = (
    "2026-01-01T00:00:{sec:02d}.{hun:02d}+00:00 host-01 conn src=10.0.0.9 "
    "dst=10.0.0.5{hun} syn_count=1 rst_count=1 bytes=60"
)


def _engine(loaded, path: Path) -> LiveEngine:
    return LiveEngine(
        loaded,
        source=SyslogTailSource(path, follow=False),
        window_seconds=60,
        stride_seconds=30,
        history=2,
        max_history=5,
    )


def test_parser_maps_known_keys_and_entities() -> None:
    event = parse_syslog_line(
        "2026-01-01T00:00:10+00:00 host-01 authd src=10.0.0.9 dst=auth-service "
        'failed_auth=yes bytes=300 note="ignore me"'
    )
    assert event is not None
    assert event.source_entity == "10.0.0.9"
    assert event.destination_entity == "auth-service"
    assert event.features == {"failed_auth": 1.0, "bytes": 300.0}
    assert event.source_format == "syslog"


def test_parser_accepts_epoch_timestamps() -> None:
    event = parse_syslog_line("1767225600 fw0 conn src=10.0.0.1 dst=10.0.0.2 bytes=840")
    assert event is not None
    assert event.timestamp.isoformat().startswith("2026-01-01T00:00:00")
    assert event.features["bytes"] == 840.0


def test_parser_skips_noise_and_empty_lines() -> None:
    assert parse_syslog_line("Jan  1 00:00:00 fw0 kernel: unrelated noise") is None
    assert parse_syslog_line("   ") is None
    assert parse_syslog_line("not-a-timestamp host app") is None


def test_parser_defaults_destination_to_app_and_keeps_zero_bytes() -> None:
    event = parse_syslog_line("2026-01-01T00:00:10+00:00 host-01 app")
    assert event is not None
    assert event.destination_entity == "app"
    assert event.features == {"bytes": 0.0}


def _write_log(path: Path) -> None:
    lines = [BENIGN.format(sec=sec) for sec in (0, 5, 10)]
    lines += [AUTH_FAILURE.format(sec=31 + k % 10) for k in range(10)]
    lines += [SCAN.format(sec=35, hun=k) for k in range(10)]
    lines += ["this line is garbage and must be skipped"]
    lines += [FLUSH]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_tail_source_streams_events_and_reports_skipped(tmp_path: Path) -> None:
    log = tmp_path / "sensor.log"
    _write_log(log)
    source = SyslogTailSource(log, follow=False)
    events: queue.Queue = queue.Queue()
    stop = threading.Event()
    source.run(events, stop)
    drained = []
    while True:
        try:
            item = events.get_nowait()
        except queue.Empty:
            break
        drained.append(item)
    parsed = [item for item in drained if isinstance(item, UnifiedEvent)]
    errors = [item for item in drained if not isinstance(item, UnifiedEvent)]
    assert len(parsed) == 24  # 3 benign + 10 auth + 10 scan + 1 flush
    assert any("skipped 1" in str(item) for item in errors)


def test_engine_detects_credential_and_recon_from_syslog(tmp_path: Path) -> None:
    log = tmp_path / "sensor.log"
    _write_log(log)
    engine = _engine(_loaded(tmp_path), log)
    engine.start()
    deadline = 20.0
    status = engine.poll()
    while status.running and deadline > 0:
        time_sleep = 0.05
        threading.Event().wait(time_sleep)
        deadline -= time_sleep
        status = engine.poll()
    engine.stop()
    assert status.events_seen == 24
    assert status.windows_emitted >= 2
    found_types = {f.attack_type for f in status.attack_findings}
    assert "credential_abuse" in found_types
    assert "reconnaissance" in found_types
    assert status.peak_probability is not None
    incidents = status.incidents
    assert incidents, "alerting findings must correlate into an incident"
    assert incidents[0].risk.score > 0


def test_benign_only_log_stays_quiet(tmp_path: Path) -> None:
    log = tmp_path / "benign.log"
    lines = [BENIGN.format(sec=sec) for sec in (0, 4, 8, 12, 16, 20)]
    lines += [FLUSH]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    engine = _engine(_loaded(tmp_path), log)
    engine.start()
    status = engine.poll()
    while status.running:
        threading.Event().wait(0.05)
        status = engine.poll()
    engine.stop()
    assert not any(f.is_alert for f in status.attack_findings)
    assert status.incidents == []
    assert status.peak_probability is not None
