"""Tests for the recursive K-step rollout module."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.baseline import save_baseline_artifacts, train_baseline
from sentinel.config import BaselineConfig
from sentinel.predict import DECISION_THRESHOLD, load_artifacts
from sentinel.rollout import (
    ROLLOUT_MODEL_VERSION,
    _stability_warnings,
    fit_transition_model,
    load_transition_model,
    rollout_forecast,
    save_transition_model,
)
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest

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
    from sentinel.evaluation import evaluate_replay

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


# -- the multi-step fit (transition-rollout-v3) ---------------------------
# v2 fitted the one-step least-squares optimum and stabilised it afterwards,
# on the stated ground that a K-step objective "is not a linear least-squares
# problem". For a linear map that is false: the K-step prediction is a fixed
# linear function of the concatenated history, so the objective is smooth in
# the parameters. These tests pin the correction and, more importantly, pin the
# measured consequence.


def test_version_is_v3() -> None:
    assert ROLLOUT_MODEL_VERSION == "transition-rollout-v3"


def test_multistep_fit_is_never_worse_than_the_one_step_optimum() -> None:
    labelled = generate_labelled_states(
        SCENARIOS[:4], seed=13, window_seconds=60, stride_seconds=60
    )
    model = fit_transition_model(
        labelled, history_length=2, scenario_ids=SCENARIOS[:4], fit_steps=3
    )
    assert model.fit_steps == 3
    # A tie to within 0.01%, not a win: the stability projection crushes *both*
    # maps to near-constant predictors, so their K-step costs converge on the
    # cost of predicting the mean. The real v3 gain is the reduced expansiveness
    # measured below, not this number.
    assert model.multistep_objective <= model.one_step_objective * 1.0001


def test_multistep_fit_is_less_expansive_than_the_one_step_fit() -> None:
    labelled = generate_labelled_states(
        SCENARIOS[:4], seed=13, window_seconds=60, stride_seconds=60
    )
    model = fit_transition_model(
        labelled, history_length=2, scenario_ids=SCENARIOS[:4], fit_steps=3
    )
    # The one-step least-squares optimum is wildly expansive; minimising error
    # at +1..+K pulls it back. That reduction is the point of v3.
    assert model.fitted_spectral_norm < model.one_step_fitted_spectral_norm


def test_fitted_norms_are_reported_before_projection() -> None:
    labelled = generate_labelled_states(
        SCENARIOS[:4], seed=13, window_seconds=60, stride_seconds=60
    )
    model = fit_transition_model(
        labelled, history_length=2, scenario_ids=SCENARIOS[:4], fit_steps=3
    )
    # Post-projection norm is pinned to the limit, so it is uninformative; the
    # pre-projection norm is the number that matters.
    assert model.fitted_spectral_norm > model.spectral_norm
    assert model.one_step_fitted_spectral_norm > model.spectral_norm


def test_a_crushed_projection_is_reported_on_the_forecast() -> None:
    # On this data the projection discards essentially the whole linear map, so
    # the rollout is close to a constant predictor. That has to travel with the
    # forecast, or a reader compares it to the world model as if it were fair.
    labelled = generate_labelled_states(
        SCENARIOS[:4], seed=13, window_seconds=60, stride_seconds=60
    )
    model = fit_transition_model(
        labelled, history_length=2, scenario_ids=SCENARIOS[:4], fit_steps=3
    )
    assert model.stability_clip < 1e-3
    warnings = _stability_warnings(model)
    assert warnings, "a crushed projection must produce a warning"
    assert "like-for-like" in warnings[0]


def test_a_healthy_projection_produces_no_warning() -> None:
    from sentinel.rollout import RolloutTransitionModel, _stability_warnings

    healthy = RolloutTransitionModel(
        model_version=ROLLOUT_MODEL_VERSION,
        history_length=2,
        feature_names=["a"],
        coefficients=[[1.0]],
        intercept=[0.0],
        residual_scale=[1.0],
        input_means=[0.0],
        input_scales=[1.0],
        training_windows=10,
        spectral_norm=0.5,
        stability_clip=1.0,
    )
    assert _stability_warnings(healthy) == []


def test_an_old_artifact_fails_loudly_rather_than_being_misapplied() -> None:
    from sentinel.rollout import RolloutTransitionModel

    with pytest.raises(ValueError, match="cannot be loaded"):
        RolloutTransitionModel(
            model_version="transition-rollout-v2",
            history_length=2,
            feature_names=["a"],
            coefficients=[[1.0]],
            intercept=[0.0],
            residual_scale=[1.0],
            input_means=[0.0],
            input_scales=[1.0],
            training_windows=10,
            spectral_norm=1.0,
        )


def test_a_payload_with_no_version_is_rejected() -> None:
    from sentinel.rollout import RolloutTransitionModel

    # The version is required, not defaulted: defaulting would let a v2 file be
    # read as v3 with invented multi-step fields.
    with pytest.raises(ValueError):
        RolloutTransitionModel(
            history_length=2,
            feature_names=["a"],
            coefficients=[[1.0]],
            intercept=[0.0],
            residual_scale=[1.0],
            input_means=[0.0],
            input_scales=[1.0],
            training_windows=10,
            spectral_norm=1.0,
        )


def test_fit_steps_must_be_positive() -> None:
    labelled = generate_labelled_states(
        SCENARIOS[:4], seed=13, window_seconds=60, stride_seconds=60
    )
    with pytest.raises(ValueError, match="fit_steps"):
        fit_transition_model(labelled, history_length=2, scenario_ids=SCENARIOS[:4], fit_steps=0)
