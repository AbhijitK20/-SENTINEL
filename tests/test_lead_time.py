"""Tests for forecast lead time and the enriched Forecast contract."""

from __future__ import annotations

from pathlib import Path

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import DECISION_THRESHOLD, forecast, load_artifacts
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"lt{i}" for i in range(5)]


def _build_baseline(tmp_path: Path):
    labelled = generate_labelled_states(SCENARIOS, seed=7, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=7)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=7,
    )
    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    scenario = manifest.test_scenarios[0]
    states = [item.state for item in labelled if item.scenario_id == scenario]
    return baseline_dir, states


def test_lead_time_present_when_threshold_crossed(tmp_path: Path) -> None:
    baseline_dir, states = _build_baseline(tmp_path)
    loaded = load_artifacts(baseline_dir)

    result = forecast(states, loaded, max_horizon=3)

    assert result.lead_time is not None
    lead = result.lead_time
    assert lead.horizon_windows == 3
    assert lead.threshold == DECISION_THRESHOLD
    if lead.lead_windows is not None:
        assert 1 <= lead.lead_windows <= 3
        crossing = next(
            point.window
            for point in result.probability_timeline
            if point.infiltration_probability >= DECISION_THRESHOLD
        )
        assert lead.lead_windows == crossing


def test_lead_time_none_is_explicit_not_zero(tmp_path: Path) -> None:
    baseline_dir, states = _build_baseline(tmp_path)
    loaded = load_artifacts(baseline_dir)

    result = forecast(states, loaded, max_horizon=3)

    lead = result.lead_time
    assert lead is not None
    peak = max(p.infiltration_probability for p in result.probability_timeline)
    if peak < DECISION_THRESHOLD:
        assert lead.lead_windows is None
    else:
        assert lead.lead_windows is not None


def test_forecast_carries_stage_mapping(tmp_path: Path) -> None:
    baseline_dir, states = _build_baseline(tmp_path)
    loaded = load_artifacts(baseline_dir)

    result = forecast(states, loaded, max_horizon=2)

    assert result.stage_mapping is not None
    mapping = result.stage_mapping
    assert mapping.stage
    assert mapping.mapping_version
    if mapping.stage != "Unknown":
        assert mapping.evidence, "non-Unknown mapping must attach observed evidence"
        assert all(ev.observed_value is not None for ev in mapping.evidence)
    else:
        assert mapping.confidence == "unknown"


def test_forecast_json_serializes_new_fields(tmp_path: Path) -> None:
    baseline_dir, states = _build_baseline(tmp_path)
    loaded = load_artifacts(baseline_dir)

    result = forecast(states, loaded, max_horizon=2)
    payload = result.model_dump_json()

    assert "stage_mapping" in payload
    assert "lead_time" in payload
    assert "mitre_reference" in payload
