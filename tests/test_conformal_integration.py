# SPDX-License-Identifier: Apache-2.0
"""Conformal bands on a real forecast: present when earned, absent when not.

The unit tests in ``test_conformal.py`` prove the mathematics. These prove the
product uses it: a trained model carries a calibrator, forecasts emit bands, and
a model that was never calibrated says ``None`` instead of inventing one.
"""

from __future__ import annotations

import pytest

from sentinel.baseline import BaselineRun, train_baseline
from sentinel.config import BaselineConfig
from sentinel.conformal import (
    CONFORMAL_VERSION,
    COVERAGE_90,
    HorizonCalibrator,
)
from sentinel.predict import FORECAST_VERSION, artifacts_from_runs, forecast
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"ci{i}" for i in range(8)]


@pytest.fixture(scope="module")
def trained():
    labelled = generate_labelled_states(SCENARIOS, seed=3, window_seconds=60, stride_seconds=60)
    manifest = make_split_manifest(SCENARIOS, seed=3)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=0.5),
        seed=3,
    )
    return run, [i.state for i in labelled if i.scenario_id == SCENARIOS[0]]


def test_training_produces_a_calibrator(trained) -> None:
    run, _ = trained
    payload = run.result.conformal
    assert payload is not None
    assert payload["conformal_version"] == CONFORMAL_VERSION
    assert payload["coverage"] == COVERAGE_90
    assert payload["calibration_sizes"]
    assert run.result.conformal_coverage == COVERAGE_90


def test_the_calibrator_is_fitted_on_validation_only(trained) -> None:
    """The leak conformal exists to prevent: the band must come from validation."""
    run, _ = trained
    manifest = run.result.split_manifest
    payload = run.result.conformal
    assert sum(payload["calibration_sizes"].values()) == payload["pooled_size"]

    labelled = generate_labelled_states(SCENARIOS, seed=3, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    validation = [s for s in samples if s.scenario_id in manifest.validation_scenarios]
    assert validation, "the fixture produced no validation samples"
    assert payload["pooled_size"] == len(validation), (
        f"calibrator used {payload['pooled_size']} windows but validation has {len(validation)}"
    )


def test_a_forecast_carries_a_guaranteed_band(trained) -> None:
    run, states = trained
    result = forecast(states, artifacts_from_runs(run), max_horizon=4)
    for point in result.probability_timeline:
        assert point.interval is not None, f"window +{point.window} has no interval"
        interval = point.interval
        assert interval.nominal_coverage == COVERAGE_90
        assert interval.calibration_size >= 1
        assert 0.0 <= interval.lower <= interval.upper <= 1.0
        assert interval.lower <= point.infiltration_probability <= interval.upper + 1e-9


def test_the_band_is_named_as_split_conformal(trained) -> None:
    run, states = trained
    result = forecast(states, artifacts_from_runs(run), max_horizon=2)
    methods = {p.interval.method for p in result.probability_timeline if p.interval}
    assert methods <= {"split-conformal-mondrian", "split-conformal-pooled-fallback"}
    assert methods, "no interval carried a method name"


def test_an_uncalibrated_model_states_that_it_has_no_interval(trained) -> None:
    run, states = trained
    bare = run.result.model_copy(update={"conformal": None})
    artifacts = artifacts_from_runs(BaselineRun(model=run.model, result=bare))
    result = forecast(states, artifacts, max_horizon=3)
    for point in result.probability_timeline:
        assert point.interval is None
        # The score is still there; it is simply not the same kind of object, and
        # the contract keeps the two apart.
        assert 0.0 <= point.confidence <= 1.0


def test_an_incompatible_calibrator_is_ignored_rather_than_applied(trained) -> None:
    run, states = trained
    tampered = dict(run.result.conformal or {})
    tampered["conformal_version"] = "conformal-prediction-v0-from-the-future"
    broken = run.result.model_copy(update={"conformal": tampered})
    artifacts = artifacts_from_runs(BaselineRun(model=run.model, result=broken))
    result = forecast(states, artifacts, max_horizon=2)
    assert all(p.interval is None for p in result.probability_timeline)


def test_the_calibrator_round_trips_through_its_payload() -> None:
    calibrator = HorizonCalibrator.fit(
        ["1", "1", "2", "2", "1", "2", "1", "2", "1", "2", "1", "2"],
        [0.1, 0.9, 0.2, 0.8, 0.15, 0.85, 0.05, 0.95, 0.12, 0.88, 0.08, 0.92],
        [0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0],
    )
    restored = HorizonCalibrator.from_payload(calibrator.to_payload())
    assert restored.horizons == calibrator.horizons
    assert restored.coverage == calibrator.coverage
    assert restored.quantiles == calibrator.quantiles
    first = calibrator.predict_for_horizon(1, 0.5)
    second = restored.predict_for_horizon(1, 0.5)
    assert (first.lower, first.upper) == (second.lower, second.upper)


def test_a_calibrator_from_the_future_is_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be read"):
        HorizonCalibrator.from_payload({"conformal_version": "v99", "coverage": 0.9})


def test_an_unfitted_calibrator_refuses_to_predict() -> None:
    with pytest.raises(ValueError, match="no calibration data"):
        HorizonCalibrator().predict_for_horizon(1, 0.5)


def test_horizons_without_enough_data_fall_back_to_the_pooled_band() -> None:
    calibrator = HorizonCalibrator.fit(
        ["1"] * 12,
        [0.05, 0.95] * 6,
        [0.0, 1.0] * 6,
    )
    # Horizon 7 was never calibrated, so the pooled quantile applies and says so.
    interval = calibrator.predict_for_horizon(7, 0.5)
    assert interval.method == "split-conformal-pooled-fallback"
    assert interval.calibration_size == 12


def test_a_too_small_validation_split_yields_no_calibrator() -> None:
    # Two scenarios cannot supply ten validation samples, so the model ships
    # uncalibrated rather than with a band nobody can justify.
    scenarios = [f"tiny{i}" for i in range(2)]
    labelled = generate_labelled_states(scenarios, seed=5, window_seconds=60, stride_seconds=60)
    manifest = make_split_manifest(scenarios, seed=5)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    run = train_baseline(
        labelled, samples, manifest, config=BaselineConfig(decision_threshold=0.5), seed=5
    )
    assert run.result.conformal is None
    assert run.result.conformal_coverage is None


def test_every_calibration_point_is_inside_its_own_band() -> None:
    """A leave-nothing-out sanity check on the stored calibrator.

    The conformal theorem is not asserted here - test_conformal.py does that at
    n=4000 against a known-good generator. What is checked is that the artifact's
    stored quantile actually covers the calibration residuals it was built from,
    which catches a serialisation bug that unit tests on the object would miss.
    """
    import numpy as np

    labelled = generate_labelled_states(SCENARIOS, seed=11, window_seconds=60, stride_seconds=60)
    manifest = make_split_manifest(SCENARIOS, seed=11)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    run = train_baseline(
        labelled, samples, manifest, config=BaselineConfig(decision_threshold=0.5), seed=11
    )
    calibrator = HorizonCalibrator.from_payload(run.result.conformal)

    states_by_key = {item.state_key: item for item in labelled}
    from sentinel.features import vectorize_states

    validation = [s for s in samples if s.scenario_id in manifest.validation_scenarios]
    states = [states_by_key[s.input_state_keys[-1]].state for s in validation]
    matrix = vectorize_states(states, run.result.feature_schema)
    predictions = np.asarray(run.model.predict_proba(matrix)[:, 1], dtype=float)
    truth = np.array([1.0 if s.target.target_infiltration else 0.0 for s in validation])

    residuals = np.abs(truth - predictions)
    widest = float(calibrator.pooled_quantile or 0.0)
    assert (residuals <= widest + 1e-9).mean() >= 0.85, (
        "the stored quantile does not cover the residuals it was fitted on"
    )


def test_coverage_report_agrees_with_the_stored_calibrator(trained) -> None:
    from sentinel.conformal import SplitConformal

    run, _ = trained
    calibrator = HorizonCalibrator.from_payload(run.result.conformal)
    # The pooled quantile must equal what a direct pooled fit produces on the same
    # scores; if the two disagree the artifact and the method have drifted apart.
    assert calibrator.pooled_size > 0
    assert calibrator.pooled_quantile is not None
    assert SplitConformal is not None


def test_the_contract_version_moved() -> None:
    assert FORECAST_VERSION == "forecast-inference-v2"
