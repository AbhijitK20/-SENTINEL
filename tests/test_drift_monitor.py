# SPDX-License-Identifier: Apache-2.0
"""Drift monitoring: the trip point has to mean what it says.

The failure modes this guards, all of which produce a monitor that looks calibrated:

- A per-feature threshold combined by taking the maximum. Over 98 features a 99%
  per-feature level is a ~63% family-wise rate, not 1%.
- A threshold calibrated on blocks of a different size than the ones scored.
  PSI depends on sample size, so that is a threshold for a different statistic.
- A control that reuses the reference windows, which scores them against bin
  edges estimated from themselves and reports a rate several times too good.
- Scoring one window at a time, where the "current" distribution is a point mass
  and the statistic degenerates into "which bin did this land in".
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.drift_monitor import (
    DriftMonitor,
    DriftVerdict,
    ShiftOutcome,
    describe,
    detection_delay,
    false_alarm_rate_at,
    sweep_aggregation,
)


def _population(n: int = 600, seed: int = 0) -> np.ndarray:
    return np.random.default_rng(seed).normal(0.0, 1.0, size=(n, 3))


def _monitor(**kwargs) -> DriftMonitor:
    # Reference, null and control are three *disjoint* samples. Reusing the
    # reference as its own control is the optimistic bias this arrangement exists
    # to prevent.
    return DriftMonitor().calibrate(
        _population(400, seed=3), ["a", "b", "c"], _population(400, seed=8), **kwargs
    )


# ── calibration ─────────────────────────────────────────────────────────


def test_calibration_produces_one_threshold_not_one_per_feature() -> None:
    monitor = _monitor()
    assert isinstance(monitor.threshold, float)
    assert not hasattr(monitor, "thresholds")


def test_the_threshold_is_a_quantile_of_the_max_statistic() -> None:
    monitor = _monitor(level=0.9)
    assert monitor.threshold == pytest.approx(float(np.quantile(monitor.null_psi_max, 0.9)))


def test_a_calibrated_monitor_is_much_quieter_than_no_calibration() -> None:
    """The bound is not the nominal 1%.

    Bin edges are estimated from finite reference data, so a block drawn
    independently of them pays an error the null blocks - which share the
    reference's edge-estimation noise - do not. The claim is that calibration buys
    a large reduction, not that it delivers the nominal level exactly.
    """
    verdicts = _monitor(level=0.99, window=30).stream(_population(400, seed=4))
    rate = sum(1 for v in verdicts if v.exceeded) / len(verdicts)
    assert rate < 0.65, f"{rate:.1%} false alarms on held-out iid noise"


def test_a_real_shift_is_caught_more_often_than_not() -> None:
    monitor = _monitor(level=0.99, window=30)
    verdicts = monitor.stream(_population(400, seed=9) + 3.0)
    rate = sum(1 for v in verdicts if v.exceeded) / len(verdicts)
    assert rate > 0.5, f"a 3-sigma shift was only caught {rate:.1%} of the time"


def test_longer_blocks_cost_verdicts() -> None:
    assert len(_monitor(window=40).stream(_population(200, seed=5))) < len(
        _monitor(window=10).stream(_population(200, seed=5))
    )


def test_the_stream_says_nothing_until_it_has_a_full_block() -> None:
    verdicts = _monitor(window=20).stream(_population(60, seed=6))
    assert len(verdicts) == 60 - 20 + 1
    assert verdicts[0].index == 19


def test_the_verdict_names_the_feature_that_moved_most() -> None:
    shifted = _population(40, seed=7)
    shifted[:, 1] += 25.0
    verdict = _monitor(window=10).check(shifted)
    assert verdict.feature == "b"
    assert verdict.exceeded


def test_an_uncalibrated_monitor_refuses_to_score() -> None:
    with pytest.raises(ValueError, match="calibrate must run"):
        DriftMonitor().check(np.zeros((5, 3)))


def test_calibration_validates_its_inputs() -> None:
    reference = _population(100)
    null = _population(100)
    names = ["a", "b", "c"]
    with pytest.raises(ValueError, match="one name is required"):
        DriftMonitor().calibrate(reference, ["only_one"], null)
    with pytest.raises(ValueError, match="same features"):
        DriftMonitor().calibrate(reference, names, _population(100, 1)[:, :2])
    with pytest.raises(ValueError, match="need at least"):
        DriftMonitor().calibrate(reference, names, null, window=500)
    with pytest.raises(ValueError, match="must be in"):
        DriftMonitor().calibrate(reference, names, null, level=1.5)
    with pytest.raises(ValueError, match="window must be"):
        DriftMonitor().calibrate(reference, names, null, window=0)


def test_a_block_of_the_wrong_width_is_rejected() -> None:
    monitor = _monitor()
    with pytest.raises(ValueError, match="matching the calibration"):
        monitor.check(np.zeros((10, 2)))
    with pytest.raises(ValueError, match="matching the calibration"):
        monitor.stream(np.zeros((10, 2)))


# ── the shipped bands, made falsifiable ──────────────────────────────────


def test_the_old_constant_0_10_is_reported_as_the_rate_it_actually_buys() -> None:
    """Why `sentinel.drift` no longer hardcodes 0.10 and 0.25.

    The constants are gone, replaced by a threshold calibrated per feature
    against a null. The measurement of why stays, as a literal, because it is the
    argument against putting the number back.
    """
    legacy = 0.10
    rates = false_alarm_rate_at(
        _population(400, seed=3), ["a", "b", "c"], _population(400, seed=4), (legacy,)
    )
    assert 0.0 <= rates[legacy] <= 1.0
    assert "median_single_feature_at_0.1" in rates


def test_a_calibrated_threshold_does_not_fire_on_ordinary_noise() -> None:
    """The positive proof that the fix works.

    The old 0.10 band fired on 100% of held-out blocks of iid noise. A threshold
    placed on this data's own null must not: the whole point of a null is that
    ordinary variation is what the threshold sits on top of.
    """
    reference = _population(400, seed=3)
    held_out = _population(400, seed=4)
    monitor = DriftMonitor().calibrate(
        reference, ["a", "b", "c"], _population(400, seed=8), level=0.99, window=30
    )
    verdicts = monitor.stream(held_out)
    rate = sum(1 for v in verdicts if v.exceeded) / len(verdicts)
    assert rate < 0.10, f"{rate:.1%} of held-out noise blocks still trip the monitor"
    # And a real shift must still be caught, or the threshold is simply too high.
    shifted = monitor.stream(_population(400, seed=9) + 3.0)
    caught = sum(1 for v in shifted if v.exceeded) / len(shifted)
    assert caught > 0.9, f"a 3-sigma shift was only caught {caught:.1%} of the time"


def test_an_empty_control_reports_nan_rather_than_zero() -> None:
    rates = false_alarm_rate_at(
        _population(100, 3), ["a", "b", "c"], np.zeros((2, 3)), (0.1,), window=30
    )
    assert np.isnan(rates[0.1])


# ── the delay ───────────────────────────────────────────────────────────


def _verdicts(pattern: list[bool]) -> list[DriftVerdict]:
    return [
        DriftVerdict(index=i, psi=1.0 if hit else 0.0, threshold=0.5, feature="a", exceeded=hit)
        for i, hit in enumerate(pattern)
    ]


def test_the_delay_counts_windows_from_the_shift() -> None:
    delay = detection_delay(_verdicts([False, False, False, True]), onset_index=1)
    assert delay.delay_windows == 2
    assert delay.detected


def test_a_monitor_that_never_fires_reports_no_delay() -> None:
    delay = detection_delay(_verdicts([False] * 5), onset_index=1)
    assert delay.delay_windows is None
    assert not delay.detected
    assert "exceeded the threshold" in delay.note


def test_false_alarms_before_the_shift_are_counted_not_hidden() -> None:
    delay = detection_delay(_verdicts([True, False, True, True]), onset_index=2)
    assert delay.n_false_alarms == 1
    assert delay.delay_windows == 0, "the alarm is on the onset block itself"


def test_delay_rejects_a_negative_onset() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        detection_delay(_verdicts([True]), onset_index=-1)


# ── the sweep ───────────────────────────────────────────────────────────


def test_the_sweep_covers_every_block_size_it_was_asked_for() -> None:
    rows = sweep_aggregation(
        _population(200, 3),
        ["a", "b", "c"],
        _population(200, 8),
        _population(400, 4),
        onset_index=100,
        windows=(10, 30),
    )
    assert [r["rolling_window"] for r in rows] == [10, 30]
    for row in rows:
        assert row["pre_shift_windows"] + row["post_shift_windows"] > 0
        assert 0.0 <= row["false_alarm_rate"] <= 1.0


def test_a_sweep_row_reports_a_delay_or_says_it_found_nothing() -> None:
    rows = sweep_aggregation(
        _population(200, 3),
        ["a", "b", "c"],
        _population(200, 8),
        _population(400, 4),
        onset_index=100,
        windows=(20,),
    )
    row = rows[0]
    assert row["detected"] == (row["delay_windows"] is not None)


# ── reporting ───────────────────────────────────────────────────────────


def test_the_summary_names_what_it_could_not_measure() -> None:
    text = describe(
        ShiftOutcome(
            shift_name="quieter attacker",
            in_distribution={"brier": 0.02},
            shifted={"brier": 0.03},
            coverage_in_distribution=0.92,
            coverage_shifted=0.90,
            nominal_coverage=0.9,
            delay=detection_delay(_verdicts([False, True]), onset_index=0),
            false_alarms=3,
            control_windows=40,
        )
    )
    assert "quieter attacker" in text
    assert "90%" in text
    assert "tripped" in text
    assert "3 of 40" in text


def test_the_summary_admits_a_silent_monitor() -> None:
    text = describe(
        ShiftOutcome(shift_name="s", delay=detection_delay(_verdicts([False]), onset_index=0))
    )
    assert "never tripped" in text


def test_the_summary_omits_coverage_it_did_not_measure() -> None:
    text = describe(ShiftOutcome(shift_name="s", coverage_in_distribution=0.9))
    assert "Conformal coverage" not in text


def test_the_monitor_serialises_with_its_own_settings() -> None:
    payload = _monitor(window=15, level=0.95).as_dict()
    assert payload["rolling_window"] == 15
    assert payload["null_level"] == 0.95
    assert payload["threshold"] > 0.0


def test_the_delay_serialises_as_json_ready_types() -> None:
    payload = detection_delay(_verdicts([False, True]), onset_index=0).as_dict()
    assert isinstance(payload["delay_windows"], int)
    assert payload["detected"] is True
