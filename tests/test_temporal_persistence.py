"""Tests for temporal weight persistence and round-trip loading.

These tests are skipped when PyTorch is unavailable, matching the project's
optional deep-learning dependency group.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import DECISION_THRESHOLD, forecast, load_artifacts
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest
from trajectory.temporal import (
    TemporalConfig,
    save_temporal_artifacts,
    train_temporal,
)

SCENARIOS = [f"tp{i}" for i in range(6)]

torch = pytest.importorskip("torch")

from trajectory.features import fit_feature_schema  # noqa: E402


def _train_and_save(tmp_path: Path, seed: int = 5):
    labelled = generate_labelled_states(SCENARIOS, seed=seed, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=seed)
    baseline = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=seed,
    )
    train_states = [i.state for i in labelled if i.scenario_id in manifest.train_scenarios]
    # Match the baseline's exclusions so both models share one feature width,
    # mirroring the production flow in scripts/run_comparison.py.
    schema = fit_feature_schema(train_states, excluded_features=BaselineConfig().excluded_features)
    temporal = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=schema,
        config=TemporalConfig(
            hidden_size=16, num_layers=1, max_epochs=3, early_stopping_patience=2
        ),
        seed=seed,
        max_horizon=2,
    )
    out = tmp_path / "temporal"
    save_temporal_artifacts(temporal, out)
    return labelled, baseline, temporal, out


def test_weights_persisted_per_horizon(tmp_path: Path) -> None:
    _, _, temporal, out = _train_and_save(tmp_path)

    for horizon in temporal.models:
        assert (out / "weights" / f"model_h{horizon}.pt").is_file()


def test_load_artifacts_uses_persisted_weights(tmp_path: Path) -> None:
    labelled, baseline, temporal, out = _train_and_save(tmp_path)

    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(baseline, baseline_dir)

    loaded = load_artifacts(baseline_dir, temporal_dir=out)

    assert set(loaded.temporal_models) == set(temporal.models), (
        "persisted weights must be available to inference"
    )
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    result = forecast(states, loaded, max_horizon=2)
    assert result.probability_timeline


def test_missing_weight_files_degrade_explicitly(tmp_path: Path) -> None:
    labelled, baseline, _, out = _train_and_save(tmp_path)

    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(baseline, baseline_dir)
    for weight in (out / "weights").glob("*.pt"):
        weight.unlink()

    loaded = load_artifacts(baseline_dir, temporal_dir=out)

    assert loaded.temporal_models == {}
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    result = forecast(states, loaded, max_horizon=2)
    assert any("decay" in w or "weights are not" in w for w in result.warnings)


def test_baseline_forecast_with_threshold_override(tmp_path: Path) -> None:
    """A calibrated threshold changes lead-time crossing without breaking contracts."""
    labelled, baseline, _, out = _train_and_save(tmp_path)

    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(baseline, baseline_dir)
    loaded = load_artifacts(baseline_dir)

    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]

    default_result = forecast(states, loaded, max_horizon=3)
    tuned_result = forecast(states, loaded, max_horizon=3, threshold=0.3)

    assert tuned_result.lead_time is not None
    assert tuned_result.lead_time.threshold == 0.3
    if default_result.lead_time and default_result.lead_time.lead_windows is not None:
        # Lower threshold can only cross earlier or at the same window.
        assert tuned_result.lead_time.lead_windows <= default_result.lead_time.lead_windows
