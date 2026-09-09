"""Tests for calibrated-threshold persistence and auto-resolution."""

from __future__ import annotations

import json
from pathlib import Path

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import DECISION_THRESHOLD, forecast, load_artifacts
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"at{i}" for i in range(5)]


def _setup(tmp_path: Path):
    labelled = generate_labelled_states(SCENARIOS, seed=17, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=17)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=17,
    )
    baseline_dir = Path(tmp_path) / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    return labelled, run, baseline_dir


def _write_calibration(baseline_dir: Path, threshold: float) -> None:
    (baseline_dir / "calibration.json").write_text(
        json.dumps({"best_threshold": threshold, "objective": "f1"}),
        encoding="utf-8",
    )


def test_calibration_json_is_auto_loaded(tmp_path: Path) -> None:
    labelled, _, baseline_dir = _setup(tmp_path)
    _write_calibration(baseline_dir, 0.35)

    loaded = load_artifacts(baseline_dir)

    assert loaded.calibrated_threshold == 0.35
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    result = forecast(states, loaded, max_horizon=2)
    assert result.lead_time is not None
    assert result.lead_time.threshold == 0.35


def test_explicit_threshold_overrides_calibration(tmp_path: Path) -> None:
    labelled, _, baseline_dir = _setup(tmp_path)
    _write_calibration(baseline_dir, 0.35)

    loaded = load_artifacts(baseline_dir)
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]

    result = forecast(states, loaded, max_horizon=2, threshold=0.7)

    assert result.lead_time is not None
    assert result.lead_time.threshold == 0.7


def test_no_calibration_falls_back_to_default(tmp_path: Path) -> None:
    labelled, _, baseline_dir = _setup(tmp_path)

    loaded = load_artifacts(baseline_dir)

    assert loaded.calibrated_threshold is None
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    result = forecast(states, loaded, max_horizon=2)
    assert result.lead_time is not None
    assert result.lead_time.threshold == DECISION_THRESHOLD


def test_invalid_calibration_is_ignored(tmp_path: Path) -> None:
    labelled, _, baseline_dir = _setup(tmp_path)
    (baseline_dir / "calibration.json").write_text(
        json.dumps({"best_threshold": 1.9}),  # out of range
        encoding="utf-8",
    )

    loaded = load_artifacts(baseline_dir)

    assert loaded.calibrated_threshold is None


def test_malformed_calibration_is_ignored(tmp_path: Path) -> None:
    labelled, _, baseline_dir = _setup(tmp_path)
    (baseline_dir / "calibration.json").write_text("not json{", encoding="utf-8")

    loaded = load_artifacts(baseline_dir)

    assert loaded.calibrated_threshold is None
