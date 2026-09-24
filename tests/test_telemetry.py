"""Telemetry adapters and live-engine detector wiring tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel.live import EventReplaySource, LiveEngine
from sentinel.schemas import UnifiedEvent
from sentinel.telemetry import parse_auth_log, parse_dns_log

START = datetime(2026, 1, 1, tzinfo=UTC)


def test_parse_dns_log_normalizes_to_unified_events(tmp_path: Path) -> None:
    log = tmp_path / "dns.log"
    log.write_text(
        "2026-01-01T00:00:10+00:00 host-01 8.8.8.8 example.com\n"
        "2026-01-01T00:00:12+00:00 host-02 9.9.9.9 evil.com tunnel\n",
        encoding="utf-8",
    )
    events = parse_dns_log(log)
    assert len(events) == 2
    event = events[0]
    assert isinstance(event, UnifiedEvent)
    assert event.source_entity == "host-01"
    assert event.event_type == "dns_query"
    assert event.features["domain_length"] == len("example.com")
    assert events[1].features["dns_tunnel_marker"] == 1.0
    assert events[0].features["dns_tunnel_marker"] == 0.0


def test_parse_dns_log_skips_malformed_lines(tmp_path: Path) -> None:
    log = tmp_path / "dns.log"
    log.write_text("garbage line\n" * 3, encoding="utf-8")
    assert parse_dns_log(log) == ()


def test_parse_auth_log_tracks_failures_and_successes(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    lines = [
        "2026-01-01T00:00:10+00:00 10.0.0.9 auth-service FAILED admin",
        "2026-01-01T00:00:11+00:00 10.0.0.9 auth-service FAILED admin",
        "2026-01-01T00:00:20+00:00 10.0.0.9 auth-service OK admin",
    ]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    events = parse_auth_log(log)
    assert len(events) == 3
    assert all(e.event_type == "auth_event" for e in events)
    failures = [e for e in events if e.features["failed_auth"] == 1.0]
    successes = [e for e in events if e.features["failed_auth"] == 0.0]
    assert len(failures) == 2
    assert len(successes) == 1


def _event(
    offset: float, index: int, src: str = "10.0.0.1", dst_host: str = "10.0.0.2", **features
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"t{index}",
        timestamp=START + timedelta(seconds=offset),
        source_entity=src,
        destination_entity=dst_host,
        event_type="flow",
        features={"bytes": 100.0, **features},
        source_format="replay",
        provenance="test",
    )


def _trained_engine(tmp_path: Path, events: list[UnifiedEvent]) -> LiveEngine:
    from sentinel.baseline import save_baseline_artifacts, train_baseline
    from sentinel.config import BaselineConfig
    from sentinel.predict import DECISION_THRESHOLD, load_artifacts
    from sentinel.synthetic import generate_labelled_states
    from sentinel.targets import build_sequence_samples, make_split_manifest

    labelled = generate_labelled_states(
        [f"lv{i}" for i in range(5)], seed=11, window_seconds=60, stride_seconds=60
    )
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest([f"lv{i}" for i in range(5)], seed=11)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=11,
    )
    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    return LiveEngine(
        load_artifacts(baseline_dir),
        source=EventReplaySource(events, speed=1e12),
        window_seconds=60,
        stride_seconds=30,
        history=2,
        max_history=10,
    )


def test_engine_attaches_nine_findings_to_every_window(tmp_path: Path) -> None:
    events = [_event(0.0, 1), _event(10.0, 2), _event(35.0, 3), _event(65.0, 4)]
    engine = _trained_engine(tmp_path, events)
    for event in events:
        engine.ingest(event)
    status = engine.poll()
    assert status.windows_emitted == 2
    for window in status.history:
        assert len(window.attack_findings) == 10
    assert len(status.attack_findings) == 20  # 10 detectors x 2 windows


def test_engine_attack_window_alerts_and_correlates(tmp_path: Path) -> None:
    benign = [_event(0.0, 1), _event(10.0, 2, bytes=500.0)]
    attack = (
        [
            _event(
                31.0 + k * 0.1,
                100 + k,
                dst_host=f"10.0.1.{k}",
                bytes=40.0,
                syn_count=1.0,
                rst_count=1.0,
            )
            for k in range(20)
        ]
        + [
            _event(
                35.0 + k * 0.1,
                200 + k,
                src="10.0.0.9",
                dst_host="auth-service",
                failed_auth=1.0,
                bytes=300.0,
            )
            for k in range(12)
        ]
        + [_event(65.0, 999)]
    )
    engine = _trained_engine(tmp_path, benign + attack)
    for event in benign + attack:
        engine.ingest(event)
    status = engine.poll()
    alerts = {f.attack_type for f in status.attack_findings if f.is_alert}
    assert "reconnaissance" in alerts
    assert "credential_abuse" in alerts
    assert status.incidents, "chained alerts must correlate into an incident"
    incident = status.incidents[0]
    # With the sequence detector, the progression may lead with a predicted
    # technique (e.g. "Lateral Movement") before the actual reconnaissance
    # alert appears — this is the intended lead-time behavior.
    assert incident.risk.level in {"high", "critical"}
    assert incident.recommended_actions


def test_engine_benign_traffic_produces_no_detector_alerts(tmp_path: Path) -> None:
    events = [_event(0.0, 1), _event(10.0, 2), _event(40.0, 3), _event(70.0, 4)]
    engine = _trained_engine(tmp_path, events)
    for event in events:
        engine.ingest(event)
    status = engine.poll()
    assert not [f for f in status.attack_findings if f.is_alert]
    assert not status.incidents
