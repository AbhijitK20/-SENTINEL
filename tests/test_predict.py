"""Tests for the forecast inference layer.

These tests build a small synthetic baseline end-to-end, save it to a
temporary directory, then load it back via ``predict.load_artifacts`` and
verify the resulting ``Forecast`` object.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from trajectory.baseline import train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import (
    DECISION_THRESHOLD,
    FORECAST_VERSION,
    forecast,
    load_artifacts,
    save_forecast,
)
from trajectory.schemas import NetworkState
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"p{i}" for i in range(5)]
START = datetime(2026, 1, 1, tzinfo=UTC)


def _states_from_sample(labelled, manifest, scenario: str) -> list[NetworkState]:
    keys = [s for s in manifest.train_scenarios if s == scenario]
    if not keys:
        return [item.state for item in labelled if item.scenario_id == scenario]
    return [item.state for item in labelled if item.scenario_id == scenario]


def _build_artifact_paths(tmp_path: Path) -> tuple[Path, Path, list[NetworkState]]:
    labelled = generate_labelled_states(SCENARIOS, seed=3, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=3)
    config = BaselineConfig(decision_threshold=DECISION_THRESHOLD)

    run = train_baseline(labelled, samples, manifest, config=config, seed=3)

    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    from trajectory.baseline import save_baseline_artifacts

    save_baseline_artifacts(run, baseline_dir)

    scenario = manifest.test_scenarios[0]
    states = _states_from_sample(labelled, manifest, scenario)
    return baseline_dir, tmp_path, states


def test_load_artifacts_round_trip(tmp_path: Path) -> None:
    baseline_dir, _, _ = _build_artifact_paths(tmp_path)
    loaded = load_artifacts(baseline_dir)

    assert loaded.baseline_result.horizon >= 1
    assert loaded.baseline_result.feature_schema.names
    assert loaded.baseline_result.split_audit.sample_counts


def test_forecast_emits_timeline_and_stage(tmp_path: Path) -> None:
    baseline_dir, _, states = _build_artifact_paths(tmp_path)
    loaded = load_artifacts(baseline_dir)

    result = forecast(states, loaded, max_horizon=3)

    assert result.horizon_windows == 3
    assert result.model_version == FORECAST_VERSION
    assert all(
        0.0 <= point.infiltration_probability <= 1.0 for point in result.probability_timeline
    )
    assert result.predicted_stage.name
    assert result.predicted_stage.probability >= 0.0
    assert result.warnings  # temporal models absent; a warning is required


def test_driving_features_are_sorted_by_absolute_contribution(tmp_path: Path) -> None:
    baseline_dir, _, states = _build_artifact_paths(tmp_path)
    loaded = load_artifacts(baseline_dir)

    result = forecast(states, loaded, max_horizon=1)

    assert result.driving_features
    magnitudes = [abs(feature.contribution) for feature in result.driving_features]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_save_forecast_writes_json(tmp_path: Path) -> None:
    baseline_dir, _, states = _build_artifact_paths(tmp_path)
    loaded = load_artifacts(baseline_dir)
    result = forecast(states, loaded, max_horizon=2)

    out = tmp_path / "forecast.json"
    written = save_forecast(result, out)
    payload = written.read_text(encoding="utf-8")

    assert written == out
    assert "infiltration_probability" in payload
    assert "predicted_stage" in payload


def test_missing_baseline_artifacts_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Baseline result not found"):
        load_artifacts(tmp_path)


def test_forecast_requires_at_least_one_state(tmp_path: Path) -> None:
    baseline_dir, _, _ = _build_artifact_paths(tmp_path)
    loaded = load_artifacts(baseline_dir)

    with pytest.raises(ValueError, match="at least one network state is required"):
        forecast([], loaded)
