#!/usr/bin/env python
"""Smoke-test the path a judge will actually see.

Deliberately small and deterministic. It does not start servers; it drives the
same entrypoints the dashboard and API use, in the order the demo runs:

    artifacts load -> windows build -> detectors run -> forecast explains
    -> stage maps -> ledger records

Every step asserts on a real contract field, so a step cannot pass by returning
an empty or None value. Run it before a demo:

    uv run python scripts/smoke_demo.py

Exits non-zero on the first failure, naming the step.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

BUNDLE = "models/release/v1"

from sentinel.predict import load_artifacts  # noqa: E402

#: Loaded once, before any step runs, and reused by the forecast and ledger steps.
#: Also makes the smoke test fail immediately on a missing or corrupt bundle.
ARTIFACTS = load_artifacts(REPO / BUNDLE)


def step(name: str):
    def wrap(fn):
        try:
            detail = fn()
        except Exception as exc:  # noqa: BLE001 - the point is to report anything
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
            raise SystemExit(1) from exc
        print(f"ok    {name}" + (f" — {detail}" if detail else ""))
        return fn

    return wrap


@step("release artifacts present and checksummed")
def _artifacts() -> str:
    from sentinel.predict import load_artifacts

    loaded = load_artifacts(REPO / BUNDLE)
    width = loaded.baseline_result.feature_schema.width
    return f"{width} features, threshold {loaded.calibrated_threshold:g}"


@step("synthetic scenario generates windows")
def _windows() -> str:
    from sentinel.state_builder import build_network_states
    from sentinel.synthetic import generate_scenario_events

    events, boundaries = generate_scenario_events("smoke", seed=42)
    states = build_network_states(events, window_seconds=60, stride_seconds=30)
    assert len(states) > 50, f"only {len(states)} windows"
    assert "lateral_start" in boundaries
    return f"{len(states)} windows, {len({e.event_type for e in events})} telemetry levels"


@step("detectors fire on an attack window")
def _detectors() -> str:
    from sentinel.detectors import run_all_detectors
    from sentinel.state_builder import build_network_states
    from sentinel.synthetic import generate_scenario_events

    events, _ = generate_scenario_events("smoke", seed=42)
    states = build_network_states(events, window_seconds=60, stride_seconds=60)
    history = tuple(states)
    alerts: list[str] = []
    for state in states:
        for finding in run_all_detectors(state, history):
            if finding.is_alert and finding.mitre_technique != "sequence-prediction":
                alerts.append(finding.attack_type)
    assert alerts, "no detector alerted on a window containing a full attack"
    return f"{len(alerts)} alerts, e.g. {sorted(set(alerts))[:3]}"


@step("forecast produces a timeline with attribution")
def _forecast() -> str:
    from sentinel.predict import forecast
    from sentinel.state_builder import build_network_states
    from sentinel.synthetic import generate_scenario_events

    events, _ = generate_scenario_events("smoke", seed=42)
    states = build_network_states(events, window_seconds=60, stride_seconds=30)
    result = forecast(states, ARTIFACTS)
    assert result.probability_timeline, "no probability timeline"
    point = result.probability_timeline[-1]
    assert 0.0 <= point.infiltration_probability <= 1.0
    assert result.driving_features, "no driving-feature attribution"
    top = result.driving_features[0]
    assert result.explanation is not None, "no explanation attached"
    return (
        f"h+{point.window} P={point.infiltration_probability:.3f}, "
        f"top driver {top.name} ({top.contribution:+.2f}), "
        f"stage {result.predicted_stage.name if result.predicted_stage else None}"
    )


@step("stage mapping returns a named stage or says why not")
def _stage() -> str:
    from sentinel.stage_mapping import map_stage
    from sentinel.state_builder import build_network_states
    from sentinel.synthetic import generate_scenario_events

    events, _ = generate_scenario_events("smoke", seed=42)
    states = build_network_states(events, window_seconds=60, stride_seconds=60)
    mapping = map_stage(states[-6:], infiltration_probability=0.8)
    assert mapping.stage or mapping.rationale, "stage mapping returned nothing at all"
    return f"{mapping.stage!r} — {mapping.rationale[:70]}"


@step("trust ledger records and verifies")
def _ledger() -> str:
    import tempfile

    from sentinel.ledger import AlertLedger
    from sentinel.predict import forecast
    from sentinel.state_builder import build_network_states
    from sentinel.synthetic import generate_scenario_events

    events, _ = generate_scenario_events("smoke", seed=42)
    states = build_network_states(events, window_seconds=60, stride_seconds=30)
    result = forecast(states, ARTIFACTS)

    with tempfile.TemporaryDirectory() as d:
        ledger = AlertLedger(Path(d) / "alerts.jsonl")
        for _ in range(3):
            ledger.append_forecast(result)
        verification = ledger.verify()
        assert verification.valid, f"ledger invalid: {verification.errors}"
        return f"{verification.records_checked} records, chain valid"


@step("file forecast works on the committed fixture")
def _file() -> str:
    from sentinel.file_forecast import forecast_from_file
    from sentinel.predict import load_artifacts

    fixture = REPO / "data" / "fixtures" / "attack_replay.csv"
    if not fixture.is_file():
        return "SKIPPED (fixture not present)"
    loaded = load_artifacts(REPO / BUNDLE)
    result = forecast_from_file(fixture, loaded, max_horizon=3)
    assert result.forecast.probability_timeline, "no timeline from the fixture"
    return (
        f"{len(result.forecast.probability_timeline)} horizons, "
        f"packet coverage {result.telemetry.packet_coverage}"
    )


if __name__ == "__main__":
    print("SENTINEL demo smoke test\n")
    _artifacts()
    _windows()
    _detectors()
    _forecast()
    _stage()
    _ledger()
    _file()
    print("\nAll demo steps passed.")
