# SPDX-License-Identifier: Apache-2.0
"""Throughput profiling: a number with a unit, and an honest label on its shape.

The trap this guards is the mislabelling. A log-log slope below 1 means the
per-item cost *falls* as the input grows, because fixed overhead amortises. An
earlier version called anything outside 0.85-1.20 "super-linear" and printed
SUPER-LINEAR in capitals for a stage whose throughput was improving, which turns
the best result in the report into the worst-looking one.
"""

from __future__ import annotations

import pytest

from sentinel.perf_profile import (
    DEFAULT_REPEATS,
    PERF_PROFILE_VERSION,
    ScalingProfile,
    StageMeasurement,
    machine,
    measure,
    render,
    report,
)


def _constant_work(payload: object) -> int:
    """O(n): the cheapest thing that scales honestly.

    Takes a range rather than a list so a large size does not allocate a large
    array, which would put memory pressure into a timing test.
    """
    return sum(payload)  # type: ignore[arg-type]


def _quadratic_work(payload: object) -> int:
    total = 0
    for index in range(len(payload)):  # type: ignore[arg-type]
        total += sum(payload[: index + 1])  # type: ignore[index]
    return total


# ── the measurement ─────────────────────────────────────────────────────


def test_a_measurement_reports_a_rate() -> None:
    m = StageMeasurement(stage="s", n_items=1000, seconds=2.0)
    assert m.items_per_second == 500.0
    assert m.microseconds_per_item == pytest.approx(2000.0)


def test_a_zero_duration_does_not_divide_by_zero() -> None:
    assert StageMeasurement("s", 10, 0.0).items_per_second == float("inf")
    assert StageMeasurement("s", 0, 1.0).microseconds_per_item == 0.0


def test_a_flat_per_item_cost_is_reported_as_linear() -> None:
    """Deterministic: the label is a function of the slope, not of the clock."""
    profile = ScalingProfile(
        stage="linear",
        measurements=[
            StageMeasurement("linear", 1_000, 0.10),
            StageMeasurement("linear", 2_000, 0.20),
            StageMeasurement("linear", 4_000, 0.40),
            StageMeasurement("linear", 8_000, 0.80),
        ],
        exponent=1.0,
        r_squared=1.0,
    )
    assert profile.shape == "linear"
    assert profile.linear
    assert "linear" in profile.verdict


@pytest.mark.performance
def test_linear_work_measures_as_linear_on_this_machine() -> None:
    """Timed, so it lives behind the performance marker with the other budgets.

    It was a default-suite test and it failed intermittently under full-suite
    load, because a shared box's run-to-run spread is larger than the difference
    between a slope of 0.9 and one of 1.1. That is not a flaky test to be retried;
    it is a wall-clock assertion in the wrong place, which is the same mistake
    `make bench-perf` documents about the budgets it measures.
    """
    profile = measure("linear", (1_000_000, 2_000_000, 4_000_000), range, _constant_work)
    assert profile.exponent == pytest.approx(1.0, abs=0.35)


def test_quadratic_work_is_reported_as_super_linear() -> None:
    profile = measure("quadratic", (40, 80, 160), lambda n: list(range(n)), _quadratic_work)
    assert profile.exponent > 1.2
    assert profile.shape == "super-linear"
    assert not profile.linear


def test_work_that_gets_cheaper_per_item_is_sub_linear_not_a_problem() -> None:
    """A slope below 1 is amortising overhead, and must not be reported as a wall.

    Timings are synthesised rather than clocked here, because the point is the
    label attached to a number and the label should not depend on the machine.
    """
    profile = ScalingProfile(
        stage="amortising",
        measurements=[
            StageMeasurement("amortising", 1_000, 0.10),
            StageMeasurement("amortising", 2_000, 0.15),
            StageMeasurement("amortising", 4_000, 0.25),
            StageMeasurement("amortising", 8_000, 0.40),
        ],
    )
    profile.exponent = 0.66
    assert profile.shape == "sub-linear"
    assert not profile.linear
    assert "sub-linear" in profile.verdict.lower()


def test_an_unfitted_profile_says_it_cannot_tell() -> None:
    profile = ScalingProfile(stage="s")
    assert profile.exponent is None
    assert profile.shape == "unknown"
    assert "Not enough" in profile.verdict


def test_too_few_sizes_gives_no_slope() -> None:
    profile = measure("one", (100,), lambda n: list(range(n)), _constant_work)
    assert profile.exponent is None
    assert profile.r_squared is None


def test_repeats_are_recorded_and_the_spread_kept() -> None:
    profile = measure(
        "s", (500,), lambda n: list(range(n)), _constant_work, repeats=DEFAULT_REPEATS
    )
    only = profile.measurements[0]
    assert only.repeats == DEFAULT_REPEATS
    assert only.spread >= 0.0


def test_the_best_run_is_reported_not_the_slowest() -> None:
    """A slow run is contaminated by the rest of the machine, not by the code."""
    import sentinel.perf_profile as module

    # perf_counter is called twice per repeat: once to start, once to stop.
    ticks = iter([0.0, 1.0, 1.0, 1.5, 1.5, 1.75])

    class _Clock:
        @staticmethod
        def perf_counter() -> float:
            return next(ticks)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module.time, "perf_counter", _Clock.perf_counter)
        profile = module.measure("s", (10,), lambda n: list(range(n)), _constant_work, repeats=3)
    only = profile.measurements[0]
    assert only.seconds == 0.25
    assert only.spread == 0.75


def test_zero_repeats_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        measure("s", (10,), lambda n: list(range(n)), _constant_work, repeats=0)


# ── the budget ──────────────────────────────────────────────────────────


def test_the_largest_size_within_a_budget_is_reported() -> None:
    """Built by hand so the budget actually binds; real timings have headroom."""
    profile = ScalingProfile(
        stage="s",
        measurements=[
            StageMeasurement("s", 200, 1.0),
            StageMeasurement("s", 400, 4.0),
        ],
        exponent=1.0,
        budget_seconds=2.0,
    )
    profile.largest_within = max(
        (m.n_items for m in profile.measurements if m.seconds <= 2.0), default=None
    )
    assert profile.largest_within == 200
    assert "budget is already binding" in profile.verdict


def test_a_budget_nothing_fits_under_says_so() -> None:
    profile = ScalingProfile(
        stage="s",
        measurements=[StageMeasurement("s", 200, 1.0)],
        exponent=1.0,
        budget_seconds=-1.0,
    )
    assert max((m.n_items for m in profile.measurements if m.seconds <= -1.0), default=None) is None


def test_no_budget_means_no_budget_claim() -> None:
    profile = measure("s", (200, 400), lambda n: list(range(n)), _constant_work)
    assert profile.budget_seconds is None
    assert "budget" not in profile.verdict


# ── the report ──────────────────────────────────────────────────────────


def test_the_report_carries_the_machine_and_its_own_limits() -> None:
    payload = report(
        [measure("s", (200, 400), lambda n: list(range(n)), _constant_work)], machine()
    )
    assert payload["version"] == PERF_PROFILE_VERSION
    assert payload["machine"]["python"]
    assert any("spread" in w for w in payload["warnings"])
    assert any("extrapolation" in w for w in payload["warnings"])


def test_the_rendered_report_shows_the_rate_and_the_shape() -> None:
    profile = measure("s", (200, 400), lambda n: list(range(n)), _constant_work)
    text = render(report([profile], machine()))
    assert "items/second" in text
    assert "us/item" in text
    assert "log-log slope" in text
    assert "Warnings" in text


def test_a_profile_serialises_to_json_ready_types() -> None:
    profile = measure("s", (200, 400), lambda n: list(range(n)), _constant_work, budget_seconds=1.0)
    payload = profile.as_dict()
    assert payload["shape"] in {"linear", "sub-linear", "super-linear"}
    assert isinstance(payload["measurements"][0]["n_items"], int)
    assert payload["largest_measured_size_within_budget"] in (None, 200, 400)
