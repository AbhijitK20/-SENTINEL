# SPDX-License-Identifier: Apache-2.0
"""What does this actually process per second, and where does it stop being linear?

``tests/test_performance.py`` asserts wall-clock budgets - 200k flow rows in
under 10s, 200k events into windows in under 5s. They pass here, with room to
spare, and that is the problem: the budgets carry no unit and no machine. Nobody
can say what throughput they buy, they will fail spuriously on a loaded CI box for
reasons that have nothing to do with this code, and they are silently machine
dependent while reading like a specification.

So this module measures the same two stages across a range of sizes and reports

- **throughput** in events per second, which is the unit the budget was missing,
- the **log-log slope**, which says whether a stage is linear or whether it has a
  quadratic wall waiting further out, and
- the **largest size that fits a stated budget on the machine that ran it**.

The extrapolation is the part to be careful about. A fitted slope over the sizes
actually run is a measurement; projecting it past the largest measured size is
arithmetic, and it is labelled as such rather than presented as a capacity
figure. The deleted ``scale/capacity.py`` invented throughput numbers, and the
whole point of doing this properly is that the numbers here came out of a clock.
"""

from __future__ import annotations

import platform
import time
from collections.abc import Callable
from dataclasses import dataclass, field

PERF_PROFILE_VERSION = "perf-profile-v1"

# Smallest, largest, and step for the sweep. Chosen to straddle the size the
# existing budget tests use (200k) so the two can be compared directly.
DEFAULT_SIZES = (25_000, 50_000, 100_000, 200_000, 400_000)
# Runs per size. A shared dev box varies by roughly 2x between runs, so one
# timing is not a measurement; the spread is reported next to the best.
DEFAULT_REPEATS = 3


@dataclass
class StageMeasurement:
    """One stage at one size, timed more than once.

    A single timing on a shared dev box is not a measurement. The same 200k-row
    read came out at 2.1s and 4.5s on consecutive runs here, so a budget tested
    against one run is a coin flip. The best of several runs is reported, because
    the slowest run is contaminated by whatever else the machine was doing, and
    the spread is reported next to it so the reader can see how much to trust it.
    """

    stage: str
    n_items: int
    seconds: float
    repeats: int = 1
    spread: float = 0.0
    note: str = ""

    @property
    def items_per_second(self) -> float:
        return self.n_items / self.seconds if self.seconds > 0 else float("inf")

    @property
    def microseconds_per_item(self) -> float:
        return self.seconds / self.n_items * 1e6 if self.n_items else 0.0

    def as_dict(self) -> dict:
        return {
            "stage": self.stage,
            "n_items": self.n_items,
            "seconds": round(self.seconds, 4),
            "repeats": self.repeats,
            "run_to_run_spread": round(self.spread, 4),
            "items_per_second": round(self.items_per_second, 1),
            "microseconds_per_item": round(self.microseconds_per_item, 4),
            "note": self.note,
        }


@dataclass
class ScalingProfile:
    """A stage's measurements, plus what can and cannot be concluded from them."""

    stage: str
    measurements: list[StageMeasurement] = field(default_factory=list)
    exponent: float | None = None
    r_squared: float | None = None
    largest_within: int | None = None
    budget_seconds: float | None = None

    @property
    def linear(self) -> bool | None:
        """True when the fitted slope is close to 1.0, i.e. cost per item is flat."""
        return None if self.exponent is None else 0.85 <= self.exponent <= 1.2

    @property
    def shape(self) -> str:
        """How cost per item behaves as the input grows.

        A slope *below* 1 is not a problem and must not be reported as one: it
        means the per-item cost falls with scale because fixed overhead amortises,
        which is the good case. The first version of this labelled anything
        outside 0.85-1.20 as "super-linear" and printed SUPER-LINEAR in capitals
        for a stage whose throughput was improving.
        """
        if self.exponent is None:
            return "unknown"
        if self.exponent < 0.85:
            return "sub-linear"
        if self.exponent > 1.2:
            return "super-linear"
        return "linear"

    @property
    def verdict(self) -> str:
        """Derived, not stored: a profile built by hand must describe itself too."""
        return _verdict(self)

    def as_dict(self) -> dict:
        return {
            "stage": self.stage,
            "measurements": [m.as_dict() for m in self.measurements],
            "exponent": None if self.exponent is None else round(self.exponent, 3),
            "r_squared": None if self.r_squared is None else round(self.r_squared, 4),
            "linear": self.linear,
            "shape": self.shape,
            "budget_seconds": self.budget_seconds,
            "largest_measured_size_within_budget": self.largest_within,
            "verdict": self.verdict,
        }


def measure(
    stage: str,
    sizes: tuple[int, ...],
    build: Callable[[int], object],
    run: Callable[[object], object],
    *,
    budget_seconds: float | None = None,
    repeats: int = DEFAULT_REPEATS,
) -> ScalingProfile:
    """Time ``run(build(n))`` at each size and fit the log-log slope.

    ``build`` and ``run`` are separate on purpose. Building the input is the
    harness's job, and timing it would report the cost of the test rather than
    the cost of the stage. ``run`` must do ``n`` units of real work - parse ``n``
    rows, window ``n`` events - rather than allocate ``n`` items and return them,
    or the profile measures the wrong thing.
    """
    if repeats < 1:
        raise ValueError("repeats must be at least one")
    profile = ScalingProfile(stage=stage, budget_seconds=budget_seconds)
    for n in sizes:
        payload = build(n)
        timings = []
        for _ in range(repeats):
            start = time.perf_counter()
            run(payload)
            timings.append(time.perf_counter() - start)
        best, worst = min(timings), max(timings)
        profile.measurements.append(
            StageMeasurement(
                stage=stage,
                n_items=n,
                seconds=best,
                repeats=repeats,
                spread=worst - best,
            )
        )
    slope, r_squared = _fit_log_log(profile.measurements)
    profile.exponent, profile.r_squared = slope, r_squared
    if budget_seconds is not None:
        profile.largest_within = max(
            (m.n_items for m in profile.measurements if m.seconds <= budget_seconds),
            default=None,
        )
    return profile


def _fit_log_log(measurements: list[StageMeasurement]) -> tuple[float | None, float | None]:
    """Least squares on log(size) against log(seconds). Slope 1.0 means linear."""
    import math

    points = [(m.n_items, m.seconds) for m in measurements if m.n_items > 0 and m.seconds > 0]
    if len(points) < 2:
        return None, None
    xs = [math.log(n) for n, _ in points]
    ys = [math.log(t) for _, t in points]
    mean_x, mean_y = sum(xs) / len(xs), sum(ys) / len(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return None, None
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / denominator
    intercept = mean_y - slope * mean_x
    residual = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys, strict=True))
    total = sum((y - mean_y) ** 2 for y in ys)
    r_squared = 1.0 - residual / total if total > 0 else 1.0
    return slope, r_squared


def _verdict(profile: ScalingProfile) -> str:
    """State the finding, including when there is not enough data for one."""
    if profile.exponent is None:
        return "Not enough distinct sizes to fit a slope."
    fit = "n/a" if profile.r_squared is None else f"{profile.r_squared:.2f}"
    parts = [
        f"Cost per item is {profile.shape} across the measured sizes "
        f"(log-log slope {profile.exponent:.2f}, r^2 {fit})."
    ]
    if profile.budget_seconds is not None and profile.largest_within is not None:
        parts.append(
            f"Largest measured size within a {profile.budget_seconds:g}s budget: "
            f"{profile.largest_within:,} items."
        )
        largest = max(m.n_items for m in profile.measurements)
        if profile.largest_within < largest:
            parts.append(
                f"{largest:,} items exceeded it, so the budget is already binding at "
                "the sizes tested."
            )
    parts.append(
        "Extrapolating past the largest measured size is arithmetic on a fitted "
        "slope, not a measurement."
    )
    noisy = [
        m for m in profile.measurements if m.spread > max(0.2 * m.seconds, 1e-9) and m.repeats > 1
    ]
    if noisy:
        parts.append(
            f"**The shape above is not resolvable on this machine**: {len(noisy)} of "
            f"{len(profile.measurements)} sizes varied by more than 20% between runs, "
            "so run-to-run noise is larger than the difference between linear and "
            "super-linear. Treat the per-item cost as roughly flat and the slope as "
            "unknown, and re-run on an idle machine before believing either."
        )
    return " ".join(parts)


def machine() -> dict:
    """Whatever is worth knowing about where the numbers came from."""
    import os

    return {
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def report(profiles: list[ScalingProfile], machine_info: dict) -> dict:
    return {
        "version": PERF_PROFILE_VERSION,
        "machine": machine_info,
        "profiles": [p.as_dict() for p in profiles],
        "warnings": [
            f"Each size is timed {DEFAULT_REPEATS} times and the best is reported, "
            "because run-to-run spread on a shared machine is comparable to the "
            "headroom being claimed. The spread is in the table next to the timing.",
            "The budget figures in tests/test_performance.py are compared here so "
            "the headroom is visible; they are unchanged.",
            "Cost per item is measured only over the sizes listed. Anything beyond "
            "the largest is an extrapolation and is labelled as one.",
        ],
    }


def render(payload: dict) -> str:
    lines = [
        "# Throughput profile",
        "",
        f"- version: `{payload['version']}`",
        f"- measured on: {payload['machine']['platform']}",
        f"- python {payload['machine']['python']}, {payload['machine']['cpu_count']} cpus",
        "",
    ]
    for profile in payload["profiles"]:
        lines += [
            f"## {profile['stage']}",
            "",
            "| items | seconds | spread | items/second | us/item |",
            "|---|---|---|---|---|",
        ]
        for m in profile["measurements"]:
            lines.append(
                f"| {m['n_items']:,} | {m['seconds']:.3f} | {m['run_to_run_spread']:.3f} | "
                f"{m['items_per_second']:,.0f} | {m['microseconds_per_item']:.2f} |"
            )
        slope = "n/a" if profile["exponent"] is None else f"{profile['exponent']:.2f}"
        fit = "n/a" if profile["r_squared"] is None else f"{profile['r_squared']:.2f}"
        shape = profile["shape"]
        lines += [
            "",
            f"- cost per item is **{shape}**: log-log slope {slope}, r^2 {fit}",
        ]
        if profile["budget_seconds"] is not None:
            largest = profile["largest_measured_size_within_budget"]
            lines.append(
                f"- largest measured size within a {profile['budget_seconds']:g}s budget: "
                + ("none of the tested sizes" if largest is None else f"{largest:,} items")
            )
        lines += ["", profile["verdict"], ""]
    lines += ["## Warnings", ""]
    lines += [f"- {w}" for w in payload["warnings"]]
    return "\n".join(lines) + "\n"


__all__ = [
    "DEFAULT_SIZES",
    "PERF_PROFILE_VERSION",
    "ScalingProfile",
    "StageMeasurement",
    "machine",
    "measure",
    "render",
    "report",
]
