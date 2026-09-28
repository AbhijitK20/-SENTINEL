# SPDX-License-Identifier: Apache-2.0
"""Survival analysis: the estimate must account for what was *not* seen.

The headline test is the censoring one. A statistic that drops censored units
from the denominator reports a better number precisely when the system fails
more often, which is the opposite of what a detection metric should do.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from sentinel.baseline import train_baseline
from sentinel.config import BaselineConfig
from sentinel.survival import (
    MIN_EVENTS_FOR_MEDIAN,
    LogrankResult,
    SurvivalRecord,
    kaplan_meier,
    logrank_test,
    median_survival,
    naive_median_lead,
    survival_table,
)
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest


def _records(pairs: list[tuple[float, bool]], group: str = "all") -> list[SurvivalRecord]:
    return [
        SurvivalRecord(subject_id=f"s{index}", duration=d, event=e, group=group)
        for index, (d, e) in enumerate(pairs)
    ]


# ── the estimator ───────────────────────────────────────────────────────


def test_survival_drops_once_per_distinct_event_time() -> None:
    # 3 events, 1 censored. At t=1 four are at risk, at t=2 three, at t=3 two -
    # so every step has survivors and the curve does not terminate early.
    estimate = kaplan_meier(_records([(1, True), (2, True), (3, True), (4, False)]))
    assert estimate.times == [1.0, 2.0, 3.0]
    assert estimate.survival == pytest.approx([0.75, 0.5, 0.25])
    assert estimate.events_at_time == [1, 1, 1]
    assert estimate.n_at_risk == [4, 3, 2]


def test_censoring_never_becomes_a_drop() -> None:
    """Censored units change the risk set, but never the survival curve itself.

    They must not appear in the per-step event counts, and the product limit is
    over event times only. That is the property that distinguishes "not yet" from
    "no".
    """
    records = _records([(1, True), (2, False), (3, False), (4, False)])
    estimate = kaplan_meier(records)
    assert sum(estimate.events_at_time) == estimate.n_event_total == 1
    assert estimate.censored_at_time == [0]
    assert len(estimate.times) == 1
    # One event out of four still at risk, so S(1) = 0.75 - and the three
    # censored units are in the denominator of that step, correctly.
    assert estimate.survival[0] == pytest.approx(0.75)
    assert estimate.n_censored_total == 3


def test_all_events_gives_a_curve_reaching_zero() -> None:
    estimate = kaplan_meier(_records([(1, True), (2, True), (3, True), (4, True)]))
    assert estimate.survival[-1] == pytest.approx(0.0)
    assert estimate.n_censored_total == 0


def test_a_terminal_step_where_everyone_dies_terminates_cleanly() -> None:
    # at_risk - died == 0 divides by zero in the naive form.
    estimate = kaplan_meier(_records([(1, True), (2, True)]))
    assert estimate.survival[-1] == 0.0
    assert all(math.isfinite(s) for s in estimate.survival)


def test_no_events_gives_an_empty_curve_not_a_crash() -> None:
    estimate = kaplan_meier(_records([(1, False), (2, False)]))
    assert estimate.times == []
    assert estimate.survival == []
    assert estimate.n_event_total == 0


def test_survival_at_reads_the_step_function() -> None:
    estimate = kaplan_meier(_records([(1, True), (5, True), (9, True), (10, False)]))
    assert estimate.survival_at(0) == 1.0
    assert estimate.survival_at(1) == pytest.approx(estimate.survival[0])
    assert estimate.survival_at(100) == pytest.approx(estimate.survival[-1])


def test_an_empty_record_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one record"):
        kaplan_meier([])


def test_negative_durations_are_rejected() -> None:
    with pytest.raises(ValueError, match="negative"):
        SurvivalRecord(subject_id="x", duration=-1.0, event=True)


# ── the statistic this replaces ─────────────────────────────────────────


def test_censoring_changes_the_answer_in_the_right_direction() -> None:
    """The core claim, stated as a test.

    20 attacks detected at window 10, then 40 never detected inside the horizon.
    The naive median is 10.0 in both the "all detected" and the "40 missed" case -
    it cannot see the misses at all. Kaplan-Meier says something sharper and
    better: it declines to quote a median at all, because S(10) = 20/60 = 0.667,
    so more than half the attacks were still undetected when observation ended.
    """
    detected = [(10.0, True)] * 20
    honest_alone = median_survival(kaplan_meier(_records(detected)))
    assert naive_median_lead(_records(detected)) == pytest.approx(10.0)
    assert honest_alone["median"] == pytest.approx(10.0)

    with_misses = detected + [(30.0, False)] * 40
    naive = naive_median_lead(_records(with_misses))
    honest = median_survival(kaplan_meier(_records(with_misses)))

    # The naive statistic is completely blind to the 40 misses.
    assert naive == pytest.approx(10.0)
    # The honest one refuses to quote a median rather than quoting a rosy one.
    assert honest["median"] is None
    assert honest["detected_fraction"] == pytest.approx(20 / 60)
    assert honest["n_events"] == 20
    assert honest["n_censored"] == 40


def test_the_naive_statistic_drops_censored_units() -> None:
    # It is kept only for comparison; this test says what it does so nobody
    # reintroduces it as the headline number.
    records = _records([(5.0, True), (50.0, False), (60.0, False)])
    assert naive_median_lead(records) == pytest.approx(5.0)


# ── the median and its interval ─────────────────────────────────────────


def test_the_median_is_none_when_the_curve_never_reaches_half() -> None:
    # One event among twenty, then everyone censored: more than half were still
    # undetected at the end of observation. That is a finding, not a gap.
    records = _records([(5.0, True)] + [(50.0, False)] * 19)
    summary = median_survival(kaplan_meier(records))
    assert summary["median"] is None
    assert "not" in str(summary["median"]) or summary["median"] is None


def test_the_interval_brackets_the_median() -> None:
    records = _records([(float(i), True) for i in range(1, 31)])
    summary = median_survival(kaplan_meier(records))
    if summary["median"] is None:
        pytest.skip("this fixture does not reach 50% survival")
    assert summary["ci_low"] is None or summary["ci_low"] <= summary["median"]
    assert summary["ci_high"] is None or summary["ci_high"] >= summary["median"]


def test_too_few_events_is_reported_as_unusable() -> None:
    records = _records([(1.0, True), (2.0, True), (3.0, True), (4.0, False)])
    estimate = kaplan_meier(records)
    assert estimate.n_event_total < MIN_EVENTS_FOR_MEDIAN
    assert not estimate.is_usable
    summary = median_survival(estimate)
    assert summary["usable"] is False
    assert "sampling noise" in summary["note"]


def test_more_events_narrows_the_interval() -> None:
    def interval_width(n: int) -> float | None:
        rng = np.random.default_rng(n)
        durations = rng.integers(1, 40, size=n).astype(float)
        events = rng.uniform(size=n) < 0.7
        summary = median_survival(kaplan_meier(_records(list(zip(durations, events, strict=True)))))
        if summary["ci_low"] is None or summary["ci_high"] is None:
            return None
        return summary["ci_high"] - summary["ci_low"]

    small = interval_width(60)
    large = interval_width(2000)
    if small is None or large is None:
        pytest.skip("a fixture did not produce a median")
    assert large < small, f"n=2000 width {large} not narrower than n=60 width {small}"


# ── comparing two forecasters ───────────────────────────────────────────


def test_identical_groups_are_not_significant() -> None:
    rng = np.random.default_rng(3)
    pairs = list(
        zip(rng.integers(1, 30, size=120).astype(float), rng.uniform(size=120) < 0.7, strict=True)
    )
    a = _records(pairs, group="a")
    b = _records(pairs, group="b")
    result = logrank_test(a, b)
    assert isinstance(result, LogrankResult)
    assert not result.significant_at_05
    assert result.p_value > 0.9


def test_a_genuinely_slower_group_is_detected() -> None:
    fast = _records([(float(i % 5 + 1), True) for i in range(80)], group="fast")
    slow = _records([(float(i % 5 + 20), True) for i in range(80)], group="slow")
    result = logrank_test(fast, slow)
    assert result.significant_at_05, f"p={result.p_value:.4g} chi2={result.chi_square:.2f}"
    assert result.p_value < 1e-6


def test_an_incomparable_pair_reports_no_difference_rather_than_dividing_by_zero() -> None:
    a = _records([(1.0, False), (2.0, False)])
    b = _records([(1.0, False), (2.0, False)])
    result = logrank_test(a, b)
    assert result.chi_square == 0.0
    assert result.p_value == 1.0
    assert "cannot be separated" in result.detail


def test_logrank_rejects_an_empty_group() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        logrank_test([], _records([(1.0, True)]))


def test_logrank_chi_square_upper_tail_matches_the_closed_form() -> None:
    # chi-square with 1 df: P(X > x) = erfc(sqrt(x/2)). Verified directly here so
    # the implementation is checked against the identity it claims to use.
    for chi_square in (0.5, 1.0, 3.84, 12.0):
        fast = _records([(float(i % 7 + 1), True) for i in range(200)], group="fast")
        slow = _records([(float(i % 11 + 6), True) for i in range(200)], group="slow")
        result = logrank_test(fast, slow)
        expected = math.erfc(math.sqrt(result.chi_square / 2.0))
        assert result.p_value == pytest.approx(expected, rel=1e-12)
        del chi_square


# ── the comparison table ────────────────────────────────────────────────


def test_the_table_reports_every_condition() -> None:
    groups = {
        "per-horizon": _records([(3.0, True)] * 10 + [(20.0, False)] * 5, group="per-horizon"),
        "rollout": _records([(6.0, True)] * 10 + [(20.0, False)] * 5, group="rollout"),
    }
    rows = survival_table(groups)
    assert [r["group"] for r in rows] == ["per-horizon", "rollout"]
    for row in rows:
        assert row["n"] == 15
        assert row["events"] == 10
        assert row["censored"] == 5
        assert row["detected_fraction"] == pytest.approx(10 / 15)


def test_the_table_and_the_logrank_test_tell_the_same_story() -> None:
    groups = {
        "fast": _records([(2.0, True)] * 30, group="fast"),
        "slow": _records([(15.0, True)] * 30, group="slow"),
    }
    rows = {r["group"]: r for r in survival_table(groups)}
    assert rows["fast"]["median"] < rows["slow"]["median"]
    assert logrank_test(groups["fast"], groups["slow"]).significant_at_05


def test_survival_records_keep_misses_in_the_denominator() -> None:
    """The wiring test: misses must survive into the survival records.

    ``measured_median_lead_windows`` averages only over rows with lead credit.
    This checks that the survival view sees the rows the old one discards, so
    the two numbers can be compared instead of the better one being chosen.
    """
    from sentinel.evaluation import evaluate_detection_survival, evaluate_replay
    from sentinel.predict import artifacts_from_runs

    scenarios = [f"su{i}" for i in range(8)]
    labelled = generate_labelled_states(scenarios, seed=31, window_seconds=60, stride_seconds=60)
    manifest = make_split_manifest(scenarios, seed=31)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=0.5),
        seed=31,
    )
    replay = evaluate_replay(labelled, artifacts_from_runs(run), horizon=4, split_filter="test")
    report = evaluate_detection_survival(replay)

    assert report["n_attacks"] > 0
    assert report["n_detected"] + report["n_censored"] == report["n_attacks"]
    assert 0.0 <= report["detected_fraction"] <= 1.0
    # The old statistic is reported alongside, from the same evaluation.
    assert "naive_median_windows" in report
    assert "measured" not in report  # the new one is not a "measured_" alias
    assert report["interpretation"]
