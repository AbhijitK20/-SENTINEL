"""Tests for the recursive K-step rollout module."""

from __future__ import annotations

from pathlib import Path

import pytest

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import DECISION_THRESHOLD, load_artifacts
from trajectory.rollout import (
    ROLLOUT_MODEL_VERSION,
    fit_transition_model,
    load_transition_model,
    rollout_forecast,
    save_transition_model,
)
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"ro{i}" for i in range(6)]


def _setup(tmp_path: Path, seed: int = 13):
    labelled = generate_labelled_states(SCENARIOS, seed=seed, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=seed)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=seed,
    )
    baseline_dir = Path(tmp_path) / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    loaded = load_artifacts(baseline_dir)
    return labelled, loaded, manifest


def test_fit_transition_model_on_training_scenarios(tmp_path: Path) -> None:
    labelled, _, manifest = _setup(tmp_path)

    model = fit_transition_model(
        labelled,
        history_length=3,
        scenario_ids=manifest.train_scenarios,
    )

    assert model.model_version == ROLLOUT_MODEL_VERSION
    assert model.training_windows > 0
    assert len(model.coefficients) == 3 * len(model.feature_names)
    assert len(model.intercept) == len(model.feature_names)
    assert all(scale > 0 for scale in model.residual_scale)


def test_fit_rejects_unknown_scenarios(tmp_path: Path) -> None:
    labelled, _, _ = _setup(tmp_path)

    with pytest.raises(ValueError, match="not present"):
        fit_transition_model(
            labelled,
            history_length=2,
            scenario_ids=["no-such-scenario"],
        )


def test_fit_rejects_impossible_history(tmp_path: Path) -> None:
    labelled, _, _ = _setup(tmp_path)

    with pytest.raises(ValueError, match="history_length must be positive"):
        fit_transition_model(labelled, history_length=0)


def test_rollout_forecast_produces_timeline_and_diagnostics(tmp_path: Path) -> None:
    labelled, loaded, manifest = _setup(tmp_path)

    transition = fit_transition_model(
        labelled, history_length=3, scenario_ids=manifest.train_scenarios
    )
    scenario = manifest.test_scenarios[0]
    states = [item.state for item in labelled if item.scenario_id == scenario]

    forecast, diagnostics = rollout_forecast(
        states,
        transition,
        loaded.baseline_model,
        loaded.baseline_result.feature_schema,
        max_horizon=4,
    )

    assert forecast.horizon_windows == 4
    assert "transition-rollout" in forecast.model_version
    assert all(0.0 <= p.infiltration_probability <= 1.0 for p in forecast.probability_timeline)
    assert forecast.lead_time is not None
    assert diagnostics.simulated_windows == 4
    assert len(diagnostics.step_delta) == 4
    assert all(delta >= 0 for delta in diagnostics.step_delta)


def test_rollout_requires_sufficient_history(tmp_path: Path) -> None:
    labelled, loaded, manifest = _setup(tmp_path)

    transition = fit_transition_model(
        labelled, history_length=5, scenario_ids=manifest.train_scenarios
    )
    scenario = manifest.test_scenarios[0]
    states = [item.state for item in labelled if item.scenario_id == scenario]

    with pytest.raises(ValueError, match="at least 5 history windows"):
        rollout_forecast(
            states[:2],
            transition,
            loaded.baseline_model,
            loaded.baseline_result.feature_schema,
            max_horizon=2,
        )


def test_transition_model_round_trip(tmp_path: Path) -> None:
    labelled, _, manifest = _setup(tmp_path)

    model = fit_transition_model(labelled, history_length=2, scenario_ids=manifest.train_scenarios)
    path = save_transition_model(model, str(Path(tmp_path) / "t.json"))
    restored = load_transition_model(path)

    assert restored == model


def test_replay_accepts_rollout_forecast_fn(tmp_path: Path) -> None:
    """The replay evaluator scores the rollout on identical windows."""
    from trajectory.evaluation import evaluate_replay

    labelled, loaded, manifest = _setup(tmp_path)

    transition = fit_transition_model(
        labelled, history_length=3, scenario_ids=manifest.train_scenarios
    )
    schema = loaded.baseline_result.feature_schema

    def rollout_fn(states, artifacts, *, max_horizon, threshold):
        return rollout_forecast(
            states,
            transition,
            artifacts.baseline_model,
            schema,
            max_horizon=max_horizon,
            threshold=threshold,
        )[0]

    evaluation = evaluate_replay(
        labelled,
        loaded,
        horizon=3,
        split_filter="test",
        min_history=3,  # rollout needs its full history length
        forecast_fn=rollout_fn,
    )

    assert evaluation.rows
    assert all("transition-rollout" not in row.predicted_stage for row in evaluation.rows)
    assert evaluation.scenarios_evaluated >= 1
