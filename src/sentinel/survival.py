# SPDX-License-Identifier: Apache-2.0
"""Time-to-detection as a survival problem, with censoring handled honestly.

The evaluation code computed ``median lead windows`` by taking the median of
forecasts that *earned* lead credit:

    leads = [row.lead_windows for row in rows if row.lead_windows is not None]

Every miss - every attack the system never warned about - was dropped from the
denominator before the median was taken. That is survivorship bias wearing a
statistic: the harder cases leave the sample, so the number that survives is a
measure of how fast the system is *when it works*, presented as how fast it is.
A deployment that detected 2 attacks in 2 minutes and missed 9 scores better on
that metric than one that detected 9 of 11 with a 90-second median.

Detection is a textbook right-censored survival problem. Each attack has a
time-to-detection; attacks never detected within the horizon are *censored*, not
discarded. Kaplan-Meier estimates the survival function under censoring using
only the fact that they lasted at least as long as observed, which is all you
know about them. That is the difference between "no data" and "not yet", and the
previous code conflated them.

What this module provides:

- :func:`kaplan_meier` - the estimator, with Greenwood variance
- :func:`median_survival` - median time-to-detection with a confidence interval
- :func:`logrank_test` - whether two forecasters differ, with a p-value
- :func:`survival_table` - a comparison of conditions in one table

Only numpy and the standard library: the chi-square upper tail with one degree
of freedom is ``erfc(sqrt(x/2))``, which is exactly right and needs no scipy.

Limits worth stating, because a survival estimate invites over-reading:

- The confidence interval is a **pointwise** band via the log-log transform
  (Brookmeyer-Crowley), evaluated at the median. It is not a simultaneous band
  over the whole curve, so quoting it as "the interval for every point" would be
  wrong.
- With fewer than ~20 events the estimate is dominated by sampling noise, and the
  module reports ``n_events`` so a reader can see that rather than infer it.
- Censoring must be non-informative: an attack that is harder *and* less likely
  to be detected would break the assumption, and nothing here can detect that.
  It is an assumption, stated once, here.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

SURVIVAL_VERSION = "survival-analysis-v1"

# Below this the estimate is not worth quoting, whatever it says.
MIN_EVENTS_FOR_MEDIAN = 5


@dataclass(frozen=True)
class SurvivalRecord:
    """One unit of follow-up: how long it lasted, and whether the event happened.

    ``duration`` is in whatever unit the caller uses - windows or seconds - and is
    carried through unchanged so the same estimator serves both.
    ``event`` is ``True`` for a detection and ``False`` for censoring.
    """

    subject_id: str
    duration: float
    event: bool
    group: str = "all"

    def __post_init__(self) -> None:
        if self.duration < 0:
            raise ValueError("duration cannot be negative")


@dataclass
class SurvivalEstimate:
    """A Kaplan-Meier curve and the bookkeeping needed to judge it."""

    times: list[float]
    survival: list[float]
    n_at_risk: list[int]
    # Per-time-step counts, one entry per row of ``times``. The totals are the
    # ``n_*_total`` fields; ``n_events`` is the convenience property below.
    events_at_time: list[int]
    censored_at_time: list[int]
    greenwood_variance: list[float]
    n_total: int
    n_event_total: int
    n_censored_total: int
    group: str = "all"

    @property
    def n_events(self) -> int:
        return self.n_event_total

    def survival_at(self, time: float) -> float:
        """S(t) by step lookup: the curve is a right-continuous step function."""
        value = 1.0
        for t, s in zip(self.times, self.survival, strict=True):
            if t <= time:
                value = s
            else:
                break
        return value

    @property
    def is_usable(self) -> bool:
        return self.n_event_total >= MIN_EVENTS_FOR_MEDIAN


def kaplan_meier(records: list[SurvivalRecord], group: str = "all") -> SurvivalEstimate:
    """Kaplan-Meier product-limit estimate with Greenwood variance.

    At each distinct event time the survival function is multiplied by
    ``1 - d/n``, where ``d`` is the number of events and ``n`` the number still
    under observation. Censored subjects leave the risk set at their censoring
    time and contribute nothing to any factor, which is the whole point: their
    unobserved future is treated as unknown, not as "no event".
    """
    if not records:
        raise ValueError("at least one record is required")
    durations = np.asarray([r.duration for r in records], dtype=float)
    is_event = np.asarray([r.event for r in records], dtype=bool)
    if np.any(durations < 0):
        raise ValueError("durations cannot be negative")

    event_times = np.unique(durations[is_event]) if is_event.any() else np.array([])
    times: list[float] = []
    survival: list[float] = []
    n_at_risk: list[int] = []
    events_at_time: list[int] = []
    censored_at_time: list[int] = []
    variance: list[float] = []

    current = 1.0
    greenwood_accumulator = 0.0
    for t in event_times:
        at_risk = int(np.sum(durations >= t))
        died = int(np.sum((durations == t) & is_event))
        censored = int(np.sum((durations == t) & ~is_event))
        if at_risk <= 0:
            continue
        # A step where everyone at risk dies leaves nothing to continue from; the
        # estimator stops there rather than dividing by zero.
        if at_risk - died == 0:
            times.append(float(t))
            survival.append(0.0)
            n_at_risk.append(at_risk)
            events_at_time.append(died)
            censored_at_time.append(censored)
            variance.append(0.0)
            break
        current *= 1.0 - died / at_risk
        if at_risk > 1:
            greenwood_accumulator += died / (at_risk * (at_risk - died))
        times.append(float(t))
        survival.append(current)
        n_at_risk.append(at_risk)
        events_at_time.append(died)
        censored_at_time.append(censored)
        variance.append(current * current * greenwood_accumulator)

    return SurvivalEstimate(
        times=times,
        survival=survival,
        n_at_risk=n_at_risk,
        events_at_time=events_at_time,
        censored_at_time=censored_at_time,
        greenwood_variance=variance,
        n_total=len(records),
        n_event_total=int(is_event.sum()),
        n_censored_total=int((~is_event).sum()),
        group=group,
    )


def _log_log_bounds(survival: float, variance: float, level: float) -> tuple[float, float]:
    """Pointwise bounds on S(t) via the complementary log-log transform.

    ``log(-log S)`` is approximately normal with variance ``d / (n (n - d))``,
    which is where the Greenwood term comes from. Inverting gives a band that
    behaves sensibly near 0 and 1, where a linear interval would run outside
    [0, 1]. This is the Brookmeyer-Crowley construction.
    """
    if survival <= 0.0 or survival >= 1.0 or variance <= 0.0:
        return (survival, survival)
    se_log_log = math.sqrt(variance) / (survival * abs(math.log(survival)))
    z = _normal_quantile(0.5 + level / 2.0)
    lower_log_log = math.log(-math.log(survival)) - z * se_log_log
    upper_log_log = math.log(-math.log(survival)) + z * se_log_log
    lower = math.exp(-math.exp(lower_log_log))
    upper = math.exp(-math.exp(upper_log_log))
    return (max(0.0, min(1.0, lower)), max(0.0, min(1.0, upper)))


def median_survival(
    estimate: SurvivalEstimate, level: float = 0.95
) -> dict[str, float | None | bool]:
    """Median time-to-detection with a pointwise confidence interval.

    Returns ``None`` for the median when the curve never crosses 0.5, which
    means "more than half the units were still undetected when observation
    ended" - a real finding, not a missing number.
    """
    median: float | None = None
    for t, s in zip(estimate.times, estimate.survival, strict=True):
        if s <= 0.5:
            median = t
            break

    low: float | None = None
    high: float | None = None
    if median is not None:
        # The lower bound is the first time the *upper* band falls to 0.5, the
        # upper bound the first time the *lower* band does.
        low = _crossing(estimate, level, want="upper")
        high = _crossing(estimate, level, want="lower")

    return {
        "median": median,
        "ci_low": low,
        "ci_high": high,
        "confidence_level": level,
        "n_total": estimate.n_total,
        "n_events": estimate.n_event_total,
        "n_censored": estimate.n_censored_total,
        "detected_fraction": (
            estimate.n_event_total / estimate.n_total if estimate.n_total else 0.0
        ),
        "usable": estimate.is_usable,
        "note": (
            ""
            if estimate.is_usable
            else (
                f"only {estimate.n_event_total} events; the estimate is dominated by "
                "sampling noise and should not be quoted as a result"
            )
        ),
    }


def _crossing(estimate: SurvivalEstimate, level: float, *, want: str) -> float | None:
    index = 0 if want == "upper" else 1
    for t, s, variance in zip(
        estimate.times, estimate.survival, estimate.greenwood_variance, strict=True
    ):
        lower, upper = _log_log_bounds(s, variance, level)
        if (upper if index == 0 else lower) <= 0.5:
            return t
    return None


@dataclass(frozen=True)
class LogrankResult:
    """A comparison between two survival curves."""

    chi_square: float
    p_value: float
    n_a: int
    n_b: int
    events_a: int
    events_b: int
    significant_at_05: bool
    detail: str


def logrank_test(
    group_a: list[SurvivalRecord], group_b: list[SurvivalRecord], level: float = 0.05
) -> LogrankResult:
    """Two-sample log-rank test.

    Under equal hazards the expected number of events in group A at each pooled
    event time is proportional to its share of the risk set. Summing the squared
    standardised deviations gives a chi-square with one degree of freedom, whose
    upper tail is ``erfc(sqrt(x/2))``.
    """
    if not group_a or not group_b:
        raise ValueError("both groups must be non-empty")
    a_durations = np.asarray([r.duration for r in group_a], dtype=float)
    a_events = np.asarray([r.event for r in group_a], dtype=bool)
    b_durations = np.asarray([r.duration for r in group_b], dtype=float)
    b_events = np.asarray([r.event for r in group_b], dtype=bool)

    all_durations = np.concatenate([a_durations, b_durations])
    all_events = np.concatenate([a_events, b_events])
    pooled_times = np.unique(all_durations[all_events]) if all_events.any() else np.array([])

    observed = 0.0
    variance = 0.0
    for t in pooled_times:
        n_a = int(np.sum(a_durations >= t))
        n_b = int(np.sum(b_durations >= t))
        d_a = int(np.sum((a_durations == t) & a_events))
        d_b = int(np.sum((b_durations == t) & b_events))
        n = n_a + n_b
        d = d_a + d_b
        if n < 2 or d == 0:
            continue
        expected = d * n_a / n
        observed += d_a - expected
        variance += (n_a * n_b * d * (n - d)) / (n * n * (n - 1))

    if variance <= 0.0:
        return LogrankResult(
            chi_square=0.0,
            p_value=1.0,
            n_a=len(group_a),
            n_b=len(group_b),
            events_a=int(a_events.sum()),
            events_b=int(b_events.sum()),
            significant_at_05=False,
            detail="no comparable event times, so the two curves cannot be separated",
        )

    chi_square = observed * observed / variance
    # Upper tail of chi-square with 1 df.
    p_value = math.erfc(math.sqrt(chi_square / 2.0))
    return LogrankResult(
        chi_square=float(chi_square),
        p_value=float(p_value),
        n_a=len(group_a),
        n_b=len(group_b),
        events_a=int(a_events.sum()),
        events_b=int(b_events.sum()),
        significant_at_05=bool(p_value < level),
        detail=(
            "the curves differ at the stated level"
            if p_value < level
            else "no evidence that the curves differ"
        ),
    )


def survival_table(
    groups: dict[str, list[SurvivalRecord]], level: float = 0.95
) -> list[dict[str, float | int | str | None | bool]]:
    """One row per condition, so a comparison is a table rather than prose."""
    rows: list[dict[str, float | int | str | None | bool]] = []
    for name, records in groups.items():
        estimate = kaplan_meier(records, group=name)
        summary = median_survival(estimate, level=level)
        rows.append(
            {
                "group": name,
                "n": estimate.n_total,
                "events": estimate.n_event_total,
                "censored": estimate.n_censored_total,
                "detected_fraction": summary["detected_fraction"],
                "median": summary["median"],
                "ci_low": summary["ci_low"],
                "ci_high": summary["ci_high"],
                "usable": summary["usable"],
                "note": summary["note"],
            }
        )
    return rows


def naive_median_lead(records: list[SurvivalRecord]) -> float | None:
    """The statistic this module replaces, kept so the difference is visible.

    Median over the *detected* records only, dropping censored units from the
    denominator. It is here to be compared against
    :func:`~sentinel.evaluation.evaluate_replay`, not to be used.
    """
    detected = [r.duration for r in records if r.event]
    return float(np.median(detected)) if detected else None


def _normal_quantile(level: float) -> float:
    """Standard-normal quantile via the inverse error function.

    Uses the rational approximation to Acklam's algorithm, accurate to about
    1.15e-9 in the central region, which is far tighter than any interval this
    module reports. Avoids a scipy dependency for one function.
    """
    if not 0.0 < level < 1.0:
        raise ValueError("level must be strictly between 0 and 1")
    a = (
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    )
    b = (
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    )
    c = (
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    )
    d = (
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e00,
        3.754408661907416e00,
    )
    p_low, p_high = 0.02425, 1 - 0.02425
    if level < p_low:
        q = math.sqrt(-2 * math.log(level))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
        )
    if level > p_high:
        q = math.sqrt(-2 * math.log(1 - level))
        return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
        )
    q = level - 0.5
    r = q * q
    return (
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5])
        * q
        / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
    )


__all__ = [
    "MIN_EVENTS_FOR_MEDIAN",
    "SURVIVAL_VERSION",
    "LogrankResult",
    "SurvivalEstimate",
    "SurvivalRecord",
    "kaplan_meier",
    "logrank_test",
    "median_survival",
    "naive_median_lead",
    "survival_table",
]
