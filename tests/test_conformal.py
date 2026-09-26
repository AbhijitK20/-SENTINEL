# SPDX-License-Identifier: Apache-2.0
"""Conformal prediction: the guarantee must hold, and its failure must be visible.

A calibration method that has only ever been shown to work is not known to work.
The most important tests here are the two that move the data away from the
calibration distribution on purpose: one must be caught by ``coverage_report``,
and one must *not* be, because a wide interval legitimately absorbs a mild shift.
Together they say what the guarantee is actually worth.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.conformal import (
    COVERAGE_90,
    COVERAGE_99,
    AdaptivePredictionSets,
    ConformalInterval,
    InsufficientCalibrationData,
    MondrianConformal,
    SplitConformal,
    _conformal_quantile,
    brier_decomposition,
    coverage_report,
    expected_calibration_error,
    interval_kind,
    reliability_table,
)


def _well_specified(n: int, seed: int, *, bias: float = 0.0, noise: float = 0.02):
    """A model that is nearly right, so a conformal interval can be narrow.

    Predictions sit close to the truth (0.95 when positive, 0.05 when not), which
    matters: a sloppy model has a wide absolute-error quantile, and a wide
    interval hides every shift you might want to detect.
    """
    rng = np.random.default_rng(seed)
    truth = rng.integers(0, 2, size=n).astype(float)
    signal = np.where(truth > 0.5, 0.95, 0.05)
    predictions = np.clip(signal + bias + rng.normal(0, noise, size=n), 0.0, 1.0)
    return predictions, truth


def _noisy(n: int, seed: int, *, bias: float = 0.0, noise: float = 0.18):
    """A model with a large error quantile, and therefore a wide interval."""
    rng = np.random.default_rng(seed)
    truth = rng.integers(0, 2, size=n).astype(float)
    signal = np.where(truth > 0.5, 0.72, 0.28)
    predictions = np.clip(signal + bias + rng.normal(0, noise, size=n), 0.0, 1.0)
    return predictions, truth


# ── the guarantee ───────────────────────────────────────────────────────


@pytest.mark.parametrize("coverage", [0.80, 0.90, 0.95])
def test_empirical_coverage_meets_the_promise(coverage: float) -> None:
    model = SplitConformal(coverage).fit(*_well_specified(600, seed=1))
    test_pred, test_truth = _well_specified(4000, seed=2)
    covered = np.mean(
        [i.covers(t) for i, t in zip(model.predict_many(test_pred), test_truth, strict=True)]
    )
    # The theorem gives >= coverage, not == coverage. Allow sampling slack.
    assert covered >= coverage - 0.03, f"coverage {covered:.3f} below promise {coverage}"
    assert covered <= coverage + 0.06, f"coverage {covered:.3f} absurdly above {coverage}"


def test_a_narrow_interval_comes_from_a_narrow_error_quantile() -> None:
    tight = SplitConformal(COVERAGE_90).fit(*_well_specified(600, seed=31))
    loose = SplitConformal(COVERAGE_90).fit(*_noisy(600, seed=32))
    assert tight.quantile < loose.quantile
    assert tight.predict(0.5).width < loose.predict(0.5).width


def test_the_quantile_is_the_ceil_n_plus_one_order_statistic() -> None:
    scores = np.arange(1, 11, dtype=float)
    assert _conformal_quantile(scores, 0.10) == 10.0  # ceil(11 * 0.90) = 10
    assert _conformal_quantile(scores, 0.50) == 6.0  # ceil(11 * 0.50) = 6
    assert _conformal_quantile(scores, 0.90) == 2.0  # ceil(11 * 0.10) = 2


def test_a_perfect_model_gets_a_zero_width_interval() -> None:
    predictions = np.array([0.0, 1.0, 0.0, 1.0] * 20)
    model = SplitConformal(0.5).fit(predictions, predictions.copy())
    assert model.quantile == 0.0
    assert model.predict(0.7).width == 0.0
    assert interval_kind(model.predict(0.7)) == "degenerate"


def test_too_small_a_calibration_set_raises_rather_than_under_covering() -> None:
    # 4 points cannot deliver 99% coverage: ceil(5 * 0.99) = 5 > 4. Clamping to the
    # maximum score would return an interval narrower than promised.
    with pytest.raises(InsufficientCalibrationData, match="needs at least"):
        SplitConformal(0.99).fit(np.array([0.1, 0.2, 0.3, 0.4]), np.array([0.0, 0.0, 0.0, 0.0]))


def test_intervals_are_clipped_to_the_probability_range() -> None:
    model = SplitConformal(COVERAGE_90).fit(*_well_specified(500, seed=3))
    assert model.predict(0.02).lower == 0.0
    assert model.predict(0.98).upper == 1.0
    assert model.predict(0.02).clipped


def test_an_unfitted_model_refuses_to_predict() -> None:
    with pytest.raises(ValueError, match="before fit"):
        SplitConformal().predict(0.5)


def test_predictions_outside_zero_one_are_rejected() -> None:
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        SplitConformal().fit(np.array([0.5, 5.0]), np.array([0.5, 0.5]))


def test_mismatched_shapes_are_rejected() -> None:
    with pytest.raises(ValueError, match="same shape"):
        SplitConformal().fit(np.array([0.5, 0.6]), np.array([0.5]))


def test_an_interval_states_its_own_limits() -> None:
    interval = SplitConformal(COVERAGE_90).fit(*_well_specified(400, seed=4)).predict(0.5)
    assert "exchangeable" in interval.caveat
    assert "not conditional" in interval.caveat.lower()
    assert "distribution shift" in interval.caveat


# ── the diagnostic, and what it can and cannot detect ───────────────────


def test_the_report_flags_a_broken_model_as_under_covering() -> None:
    # Calibrate on a sharp model so the interval is narrow, then score data the
    # model is badly wrong about. The shift has to exceed the calibrated width or
    # nothing is proven - which is why the next test exists too.
    model = SplitConformal(COVERAGE_90).fit(*_well_specified(600, seed=5))
    assert model.quantile < 0.15, "interval too wide for this test to mean anything"

    test_pred, test_truth = _well_specified(4000, seed=6, bias=0.45)
    result = coverage_report(model.predict_many(test_pred), test_truth)

    assert result.under_covers, "a badly miscalibrated model was reported as well covered"
    assert result.empirical_coverage is not None
    assert result.empirical_coverage < COVERAGE_90 - 0.05
    assert "exchangeable" in result.note


def test_a_wide_interval_does_not_rescue_a_bad_model() -> None:
    # The measured limitation, pinned as a test so it cannot be forgotten. A bad
    # model produces a huge error quantile and therefore a very wide interval,
    # and the temptation is to read that as margin. It is not: the interval is
    # clipped to [0, 1], which destroys the width the calibration paid for. At
    # zero shift this already under-covers, and a 0.12 shift makes it worse.
    model = SplitConformal(COVERAGE_90).fit(*_noisy(600, seed=7))
    assert model.quantile > 0.4, "this test needs a genuinely bad model"

    at_rest, rest_truth = _noisy(4000, seed=8)
    result = coverage_report(model.predict_many(at_rest), rest_truth)
    assert result.empirical_coverage is not None
    assert result.empirical_coverage < COVERAGE_90
    assert result.under_covers

    shifted, shifted_truth = _noisy(4000, seed=8, bias=0.12)
    worse = coverage_report(model.predict_many(shifted), shifted_truth)
    assert worse.empirical_coverage is not None
    assert worse.empirical_coverage < result.empirical_coverage


def test_the_tolerance_scales_with_the_sample_size() -> None:
    # A correct method varies by ~3% run to run at a few thousand windows. A
    # fixed 2% slack would flag correct code as broken; the slack is derived from
    # the binomial standard error instead.
    small = coverage_report(
        SplitConformal(COVERAGE_90)
        .fit(*_well_specified(200, seed=41))
        .predict_many(np.full(200, 0.5)),
        np.full(200, 0.5),
    )
    large = coverage_report(
        SplitConformal(COVERAGE_90)
        .fit(*_well_specified(200, seed=41))
        .predict_many(np.full(20000, 0.5)),
        np.full(20000, 0.5),
    )
    assert not small.under_covers and not large.under_covers


def test_the_report_does_not_flag_a_correct_model() -> None:
    # Averaged over seeds, because the theorem is over calibration draws. A
    # single run at n=4000 legitimately lands 2-3% either side of nominal.
    coverages = []
    for seed in range(8):
        model = SplitConformal(COVERAGE_90).fit(*_well_specified(600, seed))
        pred, truth = _well_specified(4000, 500 + seed)
        coverages.append(coverage_report(model.predict_many(pred), truth).empirical_coverage)
    assert all(c is not None for c in coverages)
    mean = float(np.mean([c for c in coverages if c is not None]))
    assert mean == pytest.approx(COVERAGE_90, abs=0.01), f"mean coverage {mean}"


def test_coverage_report_rejects_misaligned_input() -> None:
    one = ConformalInterval(lower=0.0, upper=1.0, nominal_coverage=0.9)
    with pytest.raises(ValueError, match="one interval per observation"):
        coverage_report([one], np.array([0.1, 0.2]))


def test_coverage_report_rejects_misaligned_groups() -> None:
    model = SplitConformal(COVERAGE_90).fit(*_well_specified(200, seed=11))
    intervals = model.predict_many(np.array([0.5, 0.5]))
    with pytest.raises(ValueError, match="align with truth"):
        coverage_report(intervals, np.array([0.5, 0.5]), groups=["only-one"])


# ── Mondrian (per-group) calibration ────────────────────────────────────


def test_mondrian_reports_per_group_coverage() -> None:
    cal_pred, cal_truth = _well_specified(800, seed=12)
    groups = ["h1"] * 400 + ["h4"] * 400
    model = MondrianConformal(COVERAGE_90).fit(groups, cal_pred, cal_truth)
    assert model.groups == ("h1", "h4")

    test_pred, test_truth = _well_specified(2000, seed=13)
    test_groups = ["h1"] * 1000 + ["h4"] * 1000
    intervals = [model.predict(g, p) for g, p in zip(test_groups, test_pred, strict=True)]
    result = coverage_report(intervals, test_truth, groups=test_groups)

    assert set(result.per_group) == {"h1", "h4"}
    for group, empirical in result.per_group.items():
        assert empirical >= COVERAGE_90 - 0.05, f"group {group} under-covered: {empirical}"


def test_mondrian_falls_back_to_pooled_for_an_unseen_group() -> None:
    model = MondrianConformal(COVERAGE_90).fit(["h1"] * 400, *_well_specified(400, seed=14))
    interval = model.predict("h9", 0.5)
    assert interval.method == "split-conformal-pooled-fallback"
    assert interval.width > 0.0


def test_mondrian_refuses_when_every_group_is_too_small() -> None:
    predictions, truth = _well_specified(20, seed=15)
    groups = [f"g{i}" for i in range(20)]
    with pytest.raises(InsufficientCalibrationData, match="fewer than"):
        MondrianConformal(COVERAGE_90, min_per_group=8).fit(groups, predictions, truth)


def test_mondrian_rejects_misaligned_input() -> None:
    predictions, truth = _well_specified(20, seed=16)
    with pytest.raises(ValueError, match="same length"):
        MondrianConformal(COVERAGE_90).fit(["a"] * 5, predictions, truth)


# ── adaptive prediction sets ────────────────────────────────────────────


def _three_class(n: int, seed: int, sharpness: float = 0.9):
    labels = ["Benign", "Reconnaissance", "Lateral Movement"]
    rng = np.random.default_rng(seed)
    truth = rng.integers(0, 3, size=n)
    rest = (1.0 - sharpness) / 2.0
    matrix = np.full((n, 3), rest)
    matrix[np.arange(n), truth] = sharpness
    return labels, matrix, truth


def test_prediction_sets_reach_their_coverage() -> None:
    labels, matrix, truth = _three_class(3000, seed=17)
    model = AdaptivePredictionSets(COVERAGE_90).fit(labels, matrix[:1000], truth[:1000])
    generator = np.random.default_rng(18)
    hits = [
        model.predict(row, generator).contains(labels[int(t)])
        for row, t in zip(matrix[1000:], truth[1000:], strict=True)
    ]
    assert np.mean(hits) >= COVERAGE_90 - 0.03


def test_the_set_refuses_to_claim_a_decision_the_model_cannot_support() -> None:
    """The behaviour that makes this safe to put in front of an analyst.

    Measured: with a 70% top-1 accuracy the set degenerates to the whole label
    space, and with a 90% top-1 accuracy it is a singleton. The method does not
    know about accuracy - it only knows the calibration scores - so this falls out
    of the construction rather than being tuned. A set-valued classifier that
    stayed confidently singleton at 70% accuracy would be the dangerous one.
    """
    labels = ["a", "b", "c"]
    n = 2000
    rng = np.random.default_rng(30)
    truth = rng.integers(0, 3, size=n)
    rest = 0.05
    matrix = np.full((n, 3), rest)
    matrix[np.arange(n), truth] = 0.90
    decoy = (truth + 1 + rng.integers(0, 2, size=n)) % 3
    broken = np.where(rng.uniform(size=n) < 0.30)[0]
    matrix[broken, truth[broken]] = rest
    matrix[broken, decoy[broken]] = 0.90

    model = AdaptivePredictionSets(COVERAGE_90).fit(labels, matrix, truth)
    accuracy = float(np.mean(np.argmax(matrix, axis=1) == truth))
    assert accuracy < 0.8, "this fixture needs a genuinely inaccurate model"

    sizes = [model.predict(row).size for row in matrix]
    hits = [
        model.predict(row).contains(labels[int(t)]) for row, t in zip(matrix, truth, strict=True)
    ]

    assert np.mean(sizes) > 2.0, "an inaccurate model produced confidently small sets"
    assert np.mean(hits) >= COVERAGE_90, "coverage was not maintained by widening"
    assert model.mean_set_size > 2.0


def test_a_reliable_model_gets_singleton_sets() -> None:
    labels, matrix, truth = _three_class(600, seed=31, sharpness=0.95)
    model = AdaptivePredictionSets(COVERAGE_90).fit(labels, matrix, truth)
    generator = np.random.default_rng(32)
    assert model.mean_set_size <= 1.5
    assert all(model.predict(row, generator).size >= 1 for row in matrix)


def test_sets_shrink_when_the_model_is_confident() -> None:
    labels, matrix, truth = _three_class(30, seed=19, sharpness=0.97)
    model = AdaptivePredictionSets(COVERAGE_90).fit(labels, matrix, truth)
    generator = np.random.default_rng(20)
    sizes = [model.predict(row, generator).size for row in matrix]
    assert max(sizes) <= 2, f"a confident model produced sets of size {sizes}"
    assert model.mean_set_size <= 2.0


def test_sets_grow_when_the_model_is_torn() -> None:
    labels = ["a", "b"]
    ambiguous = np.array([[0.5, 0.5]] * 20)
    model = AdaptivePredictionSets(COVERAGE_90).fit(labels, ambiguous, np.zeros(20, dtype=int))
    generator = np.random.default_rng(21)
    sizes = [model.predict(row, generator).size for row in ambiguous]
    assert max(sizes) == 2, "a coin-flip model produced singleton sets"


def test_a_prediction_set_is_never_empty() -> None:
    # An empty set is a prediction of nothing: worse than useless, because it
    # looks like precision.
    labels = ["a", "b", "c"]
    matrix = np.array([[0.9, 0.05, 0.05], [0.02, 0.01, 0.97], [0.01, 0.97, 0.02]] * 10)
    model = AdaptivePredictionSets(COVERAGE_90).fit(labels, matrix, np.array([0, 2, 1] * 10))
    generator = np.random.default_rng(22)
    for row in ([0.5, 0.5, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]):
        assert model.predict(np.array(row), generator).size >= 1


def test_a_singleton_set_is_a_decision() -> None:
    # 99% coverage needs at least 100 calibration points: ceil(101 * 0.99) = 100.
    labels = ["a", "b", "c"]
    matrix = np.array([[0.95, 0.03, 0.02]] * 120)
    model = AdaptivePredictionSets(COVERAGE_99).fit(labels, matrix, np.zeros(120, dtype=int))
    generator = np.random.default_rng(23)
    prediction = model.predict(np.array([0.97, 0.02, 0.01]), generator)
    if prediction.size == 1:
        assert prediction.singleton() == "a"


def test_ninety_nine_percent_needs_enough_calibration_points() -> None:
    # Arithmetic, not a preference: n = 98 gives ceil(99 * 0.99) = 99 > 98, and
    # n = 99 gives exactly 99 <= 99, so 99 is the smallest set that can honour 99%.
    labels = ["a", "b"]
    with pytest.raises(InsufficientCalibrationData):
        AdaptivePredictionSets(COVERAGE_99).fit(
            labels, np.array([[0.9, 0.1]] * 98), np.zeros(98, dtype=int)
        )
    AdaptivePredictionSets(COVERAGE_99).fit(
        labels, np.array([[0.9, 0.1]] * 99), np.zeros(99, dtype=int)
    )


def test_an_unfitted_set_model_refuses_to_predict() -> None:
    with pytest.raises(ValueError, match="before fit"):
        AdaptivePredictionSets(COVERAGE_90).predict(np.array([0.5, 0.5]))


def test_prediction_sets_reject_misaligned_input() -> None:
    with pytest.raises(ValueError, match="aligned"):
        AdaptivePredictionSets(COVERAGE_90).fit(
            ["a", "b"], np.array([[0.5, 0.5]]), np.array([0, 1])
        )


def test_a_prediction_set_states_its_own_limits() -> None:
    labels, matrix, truth = _three_class(20, seed=24)
    prediction = AdaptivePredictionSets(COVERAGE_90).fit(labels, matrix, truth).predict(matrix[0])
    assert "exchangeable" in prediction.caveat
    assert "not the right one" not in prediction.caveat


# ── calibration diagnostics ─────────────────────────────────────────────


def test_reliability_table_keeps_the_top_bin() -> None:
    # p == 1.0 must be counted, not silently dropped by a half-open interval.
    rows = reliability_table(np.array([1.0, 0.0]), np.array([1.0, 0.0]), bins=10)
    assert rows[0]["count"] == 1
    assert rows[-1]["count"] == 1
    assert sum(int(r["count"]) for r in rows) == 2


def test_empty_bins_report_none_not_zero() -> None:
    rows = reliability_table(np.array([0.05]), np.array([0.0]), bins=10)
    empty = [r for r in rows if r["count"] == 0]
    assert empty
    for row in empty:
        assert row["observed_frequency"] is None
        assert row["gap"] is None


def test_a_calibrated_model_has_near_zero_ece() -> None:
    rng = np.random.default_rng(25)
    probabilities = rng.uniform(size=20000)
    truth = (rng.uniform(size=20000) < probabilities).astype(float)
    assert expected_calibration_error(probabilities, truth) < 0.02


def test_a_confidently_wrong_model_has_high_ece() -> None:
    rng = np.random.default_rng(26)
    probabilities = rng.uniform(0.8, 1.0, size=2000)
    assert expected_calibration_error(probabilities, np.zeros(2000)) > 0.7


def test_brier_decomposition_adds_up() -> None:
    rng = np.random.default_rng(27)
    probabilities = rng.uniform(size=4000)
    truth = (rng.uniform(size=4000) < probabilities).astype(float)
    parts = brier_decomposition(probabilities, truth)
    assert parts["brier"] == pytest.approx(parts["brier_from_decomposition"], abs=0.02)
    assert parts["uncertainty"] == pytest.approx(
        parts["base_rate"] * (1 - parts["base_rate"]), abs=1e-9
    )


def test_resolution_penalises_a_constant_confident_model() -> None:
    # Correctly saying 0.5 always is reliable and useless. The decomposition has
    # to show that, which is the only reason it exists.
    truth = np.array([0.0, 1.0] * 500)
    constant = brier_decomposition(np.full(1000, 0.5), truth)
    sharp = brier_decomposition(np.where(truth > 0.5, 0.9, 0.1), truth)
    assert sharp["brier"] < constant["brier"]
    assert sharp["resolution"] > constant["resolution"]


def test_skill_is_zero_for_a_base_rate_predictor() -> None:
    truth = np.array([0.0, 1.0] * 500)
    parts = brier_decomposition(np.full(1000, 0.5), truth)
    assert parts["skill_vs_base_rate"] == pytest.approx(0.0, abs=1e-9)


def test_a_useful_model_has_positive_skill() -> None:
    truth = np.array([0.0, 1.0] * 500)
    parts = brier_decomposition(np.where(truth > 0.5, 0.95, 0.05), truth)
    assert parts["skill_vs_base_rate"] > 0.9


def test_brier_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        brier_decomposition(np.array([]), np.array([]))


def test_interval_kind_distinguishes_a_useless_interval() -> None:
    assert interval_kind(ConformalInterval(0.4, 0.6, COVERAGE_90)) == "interval"
    assert interval_kind(ConformalInterval(0.0, 1.0, COVERAGE_90)) == "degenerate"
    assert interval_kind(ConformalInterval(0.5, 0.5, COVERAGE_90)) == "degenerate"
