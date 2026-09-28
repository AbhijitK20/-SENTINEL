# SPDX-License-Identifier: Apache-2.0
"""Isotonic recalibration: correct the scale, never the ranking.

These tests exist because the failure being fixed is quiet. A badly-scaled head
still ranks well, still looks accurate at its default threshold, and quietly
misleads everywhere in between.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.conformal import brier_decomposition, expected_calibration_error
from sentinel.isotonic import (
    ISOTONIC_VERSION,
    InsufficientRecalibrationData,
    IsotonicCalibrator,
    logit,
    recalibration_outcome,
    reliability_curve,
    sigmoid,
)

# The shape measured from the world model's risk head: good ranking, wrong scale.
# Anything in the mid-range almost never happens; only near 1.0 is it frequent.
REAL_MID_RANGE_FAILURE = np.clip(
    np.where(np.random.default_rng(0).uniform(size=4000) < 0.12, 0.99, 0.75), 0.0, 1.0
)
REAL_LABELS = (np.random.default_rng(1).uniform(size=4000) < REAL_MID_RANGE_FAILURE).astype(float)


def _step_shaped(n: int, seed: int):
    """Well-ranked, badly-scaled - the shape measured from the world model.

    Scores spread continuously so the ranking is informative, while the true event
    rate follows a much flatter curve. A model reporting 0.75 is wrong by about
    0.32, but it still orders the windows correctly, which is exactly the failure
    isotonic exists to fix.

    Generating labels with ``P(y) = score`` would be a trap: that is perfectly
    calibrated by construction, so it would test nothing.
    """
    rng = np.random.default_rng(seed)
    scores = rng.uniform(0.05, 0.98, size=n)
    true_rate = scores**3  # monotone, informative ranking, badly scaled
    labels = (rng.uniform(size=n) < true_rate).astype(float)
    return scores, labels


# ── monotonicity is the whole contract ──────────────────────────────────


def test_recalibration_never_decreases_with_score() -> None:
    scores = np.linspace(0.0, 1.0, 200)
    labels = (np.random.default_rng(2).uniform(size=200) < scores).astype(float)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    recalibrated = calibrator.predict_many(scores)
    assert np.all(np.diff(recalibrated) >= -1e-12)


def test_recalibration_cannot_invert_two_scores() -> None:
    """If a < b then f(a) <= f(b). A "correction" that inverts is a new model."""
    scores, labels = _step_shaped(600, seed=3)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    for low, high in ((0.2, 0.4), (0.6, 0.8), (0.9, 0.95)):
        a = calibrator.predict(low)
        b = calibrator.predict(high)
        assert a <= b + 1e-12, f"f({low})={a} > f({high})={b}"


def test_the_outcome_reports_monotonicity_as_held() -> None:
    scores, labels = _step_shaped(500, seed=4)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    outcome = recalibration_outcome(scores, labels, calibrator)
    assert outcome.ranking_unchanged, "the fit is not monotone and was reported as such"


# ── it fixes the measured failure ───────────────────────────────────────


def test_the_mid_range_failure_is_corrected() -> None:
    scores, labels = _step_shaped(1200, seed=5)
    before_ece = expected_calibration_error(scores, labels)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    after = calibrator.predict_many(scores)
    after_ece = expected_calibration_error(after, labels)

    assert before_ece > 0.10, "the fixture is supposed to be badly miscalibrated"
    assert after_ece < before_ece / 2, f"ECE {before_ece:.3f} -> {after_ece:.3f}"


def test_brier_improves_on_held_out_data() -> None:
    fit_scores, fit_labels = _step_shaped(800, seed=6)
    calibrator = IsotonicCalibrator.fit(fit_scores, fit_labels)
    test_scores, test_labels = _step_shaped(800, seed=7)

    outcome = recalibration_outcome(test_scores, test_labels, calibrator)
    assert outcome.improved, (
        f"Brier {outcome.brier_before:.4f} -> {outcome.brier_after:.4f} on held-out data"
    )
    assert outcome.brier_before - outcome.brier_after > 0.01


def test_bias_moves_towards_zero() -> None:
    scores, labels = _step_shaped(1000, seed=8)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    outcome = recalibration_outcome(scores, labels, calibrator)
    assert abs(outcome.bias_after) < abs(outcome.bias_before)


def test_recalibration_reports_how_far_it_moved_things() -> None:
    scores, labels = _step_shaped(600, seed=9)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    assert calibrator.mean_absolute_shift > 0.0
    assert calibrator.n_fit == 600
    assert calibrator.fit_base_rate == pytest.approx(labels.mean(), abs=1e-9)


# ── the guard rails ─────────────────────────────────────────────────────


def test_too_few_points_refuses_to_fit() -> None:
    # A curve fitted on 10 points reproduces them and generalises to nothing.
    with pytest.raises(InsufficientRecalibrationData, match="memorise"):
        IsotonicCalibrator.fit(np.array([0.2, 0.8] * 5), np.array([0.0, 1.0] * 5))


def test_the_minimum_is_configurable() -> None:
    scores = np.linspace(0.1, 0.9, 30)
    labels = (np.random.default_rng(10).uniform(size=30) < scores).astype(float)
    IsotonicCalibrator.fit(scores, labels, min_points=30)
    with pytest.raises(InsufficientRecalibrationData):
        IsotonicCalibrator.fit(scores, labels, min_points=31)


def test_an_unfitted_calibrator_refuses_to_predict() -> None:
    with pytest.raises(ValueError, match="before fit"):
        IsotonicCalibrator().predict(0.5)
    with pytest.raises(ValueError, match="before fit"):
        IsotonicCalibrator().predict_many(np.array([0.5]))


def test_mismatched_shapes_are_rejected() -> None:
    scores = np.linspace(0.1, 0.9, 40)
    with pytest.raises(ValueError, match="same shape"):
        IsotonicCalibrator.fit(scores, np.zeros(10))


def test_labels_outside_zero_one_are_rejected() -> None:
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        IsotonicCalibrator.fit(np.linspace(0.1, 0.9, 40), np.full(40, 2.0))


def test_a_perfectly_calibrated_model_is_not_damaged() -> None:
    # Isotonic fitted and scored in-sample slightly overfits the empirical CDF,
    # so an already-calibrated model can come out a touch worse. The bar is
    # "not materially worse", measured on held-out data.
    rng = np.random.default_rng(11)
    fit_scores = rng.uniform(size=6000)
    fit_labels = (rng.uniform(size=6000) < fit_scores).astype(float)
    test_scores = rng.uniform(size=6000)
    test_labels = (rng.uniform(size=6000) < test_scores).astype(float)

    calibrator = IsotonicCalibrator.fit(fit_scores, fit_labels)
    outcome = recalibration_outcome(test_scores, test_labels, calibrator)
    assert outcome.ranking_unchanged
    assert outcome.brier_after < outcome.brier_before * 1.05, (
        f"recalibrating an already-calibrated model cost "
        f"{outcome.brier_after - outcome.brier_before:+.4f} Brier"
    )


# ── serialisation, because it ships inside the artifact ─────────────────


def test_the_calibrator_round_trips() -> None:
    scores, labels = _step_shaped(300, seed=12)
    original = IsotonicCalibrator.fit(scores, labels)
    restored = IsotonicCalibrator.from_payload(original.to_payload())

    assert restored.thresholds == original.thresholds
    assert restored.values == original.values
    assert restored.n_fit == original.n_fit
    for probe in (0.0, 0.3, 0.75, 0.99, 1.0):
        assert restored.predict(probe) == pytest.approx(original.predict(probe))


def test_a_calibrator_from_the_future_is_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be read"):
        IsotonicCalibrator.from_payload({"isotonic_version": "v0", "values": [0.5]})


def test_the_version_is_recorded() -> None:
    assert ISOTONIC_VERSION == "isotonic-recalibration-v1"


def test_predictions_stay_inside_the_probability_range() -> None:
    scores, labels = _step_shaped(300, seed=13)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    out = calibrator.predict_many(np.array([-5.0, 0.5, 5.0]))
    assert np.all(out >= 0.0) and np.all(out <= 1.0)


def test_a_tampered_curve_cannot_escape_the_range() -> None:
    calibrator = IsotonicCalibrator(thresholds=[0.5], values=[1.4])
    assert calibrator.predict(0.9) <= 1.0


def test_a_sharp_boundary_is_not_reliably_recovered() -> None:
    """Documented limit: isotonic cannot place a step it has little data for.

    A step in the true rate at 0.80 is only recovered if a block boundary lands
    near it, and where those boundaries fall depends on where the observations
    happen to be. Measured over seeds, a sparse fit and a dense fit are equally
    likely to straddle the step - more data helps on average but does not
    guarantee the step is placed.

    This was found by a test asserting the opposite, and it passed by luck. The
    defensible conclusion is not "use more data" but "check the held-out
    improvement", which is what :func:`recalibration_outcome` is for.
    """
    truth = np.array([0.02, 0.02, 0.02, 0.85, 0.85])
    probe = np.array([0.60, 0.70, 0.78, 0.82, 0.90])

    def sharp(n: int, seed: int):
        local = np.random.default_rng(seed)
        scores = local.uniform(0.5, 0.95, size=n)
        rate = np.where(scores < 0.80, 0.02, 0.85)
        return scores, (local.uniform(size=n) < rate).astype(float)

    errors = []
    for seed in range(6):
        fit_scores, fit_labels = sharp(2000, 30 + seed)
        calibrator = IsotonicCalibrator.fit(fit_scores, fit_labels)
        # Always monotone, whatever the data looked like.
        assert np.all(np.diff(calibrator.predict_many(np.sort(probe))) >= -1e-12)
        errors.append(float(np.mean(np.abs(calibrator.predict_many(probe) - truth))))

    # Some fits straddle the step badly, which is the point: a step is not
    # reliably recovered, so adoption has to be justified by held-out gain.
    assert max(errors) > 0.05, f"every seed happened to fit the step well: {errors}"


# ── helpers used by callers ─────────────────────────────────────────────


def test_logit_and_sigmoid_round_trip() -> None:
    probabilities = np.array([0.1, 0.5, 0.9])
    assert np.allclose(sigmoid(logit(probabilities)), probabilities)


def test_logit_pins_the_endpoints_to_a_finite_value() -> None:
    # 1e-12, not 0: an infinite log-odds would poison any downstream average.
    assert logit(0.0) == pytest.approx(-27.63, abs=0.01)
    assert logit(1.0) == pytest.approx(27.63, abs=0.01)
    assert np.isfinite(logit(0.0)) and np.isfinite(logit(1.0))


def test_sigmoid_is_stable_at_large_magnitudes() -> None:
    out = sigmoid(np.array([-800.0, 800.0]))
    assert np.all(np.isfinite(out))
    assert out[0] == pytest.approx(0.0)
    assert out[1] == pytest.approx(1.0)


def test_the_reliability_curve_is_the_same_source_as_the_plot() -> None:
    scores, labels = _step_shaped(200, seed=14)
    rows = reliability_curve(scores, labels, bins=5)
    assert len(rows) == 5
    assert sum(int(r["count"]) for r in rows) == 200


def test_the_decomposition_agrees_with_the_brier_after_recalibration() -> None:
    scores, labels = _step_shaped(500, seed=15)
    calibrator = IsotonicCalibrator.fit(scores, labels)
    after = calibrator.predict_many(scores)
    direct = brier_decomposition(after, labels)["brier"]
    outcome = recalibration_outcome(scores, labels, calibrator)
    assert outcome.brier_after == pytest.approx(direct, abs=1e-9)
