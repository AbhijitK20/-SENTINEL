# SPDX-License-Identifier: Apache-2.0
"""Conformal prediction: coverage guarantees instead of confidence vibes.

Every probability this product emits was, until now, accompanied by a number
called ``confidence``. That number was a composite of the baseline's PR-AUC, the
distance between two models' predictions, and how far the probability sat from
the decision boundary. It was an opinion about the opinion, and the
``ProbabilityPoint`` docstring had to admit it was "not a posterior interval".

Conformal prediction replaces it with a guarantee. Split conformal needs no
distributional assumption at all:

1. Fit the model on train.
2. Score how wrong it was on a held-out **calibration** split.
3. Take the ``ceil((n+1)(1-alpha))``-th smallest score as a threshold ``q``.
4. At inference, emit ``[p - q, p + q]`` clipped to ``[0, 1]``.

Then ``P(true value falls in the interval) >= 1 - alpha`` **exactly**, for any
model and any data, finite-sample, no asymptotics. That is a theorem (Lei et
al. 2018, Vovk et al. 2005), not a hope.

Three things this module refuses to do, because each would be a lie:

- **No claim of conditional coverage.** The guarantee is *marginal*: averaged
  over the data distribution. Coverage for a specific window, or for a specific
  horizon, is not guaranteed. :class:`MondrianConformal` narrows this by
  calibrating separately per group, which trades a real bias/variance cost for
  tighter per-group behaviour - but the guarantee is still marginal within each
  group, not conditional on any feature.
- **No guarantee under distribution shift.** Exchangeability of the calibration
  and test data is the assumption. If traffic changes, coverage is not covered
  by the theorem. :func:`coverage_report` exists to make that checkable, and
  ``test_conformal.py`` deliberately breaks the guarantee to prove the
  diagnostic catches it.
- **No calibration on the test split.** The contract takes calibration scores
  explicitly, so a caller cannot quietly fit the quantile on the data it is
  scoring.

Only numpy and the standard library, so the offline dependency set is unchanged.
The inverse-normal-quantile helper that used to live here was dead code and also
wrong - it called ``math.erf`` where the inverse needs ``math.erf``'s inverse.
:mod:`sentinel.survival` has a correct one, where it is actually used.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal

import numpy as np

CONFORMAL_VERSION = "conformal-prediction-v1"

# Coverage levels this product is willing to publish. They are named constants
# rather than free parameters so that an artifact records which one it was built
# with, and a 50% "interval" cannot be quietly presented as a 90% one.
COVERAGE_90 = 0.90
COVERAGE_95 = 0.95
COVERAGE_99 = 0.99
PUBLISHABLE_COVERAGE = (COVERAGE_90, COVERAGE_95, COVERAGE_99)


class InsufficientCalibrationData(ValueError):
    """Raised when the calibration split is too small for the requested alpha.

    The conformal quantile is the ``ceil((n+1)(1-alpha))``-th order statistic
    of ``n`` scores. If that index exceeds ``n`` the requested coverage is
    unreachable at this sample size, and the honest response is to refuse rather
    than clamp - clamping would silently under-cover.
    """


@dataclass(frozen=True)
class ConformalInterval:
    """A prediction interval whose coverage is guaranteed under exchangeability."""

    lower: float
    upper: float
    nominal_coverage: float
    method: str = "split-conformal-symmetric"
    calibration_size: int = 0
    quantile: float = 0.0
    clipped: bool = False
    caveat: str = (
        "Marginal coverage on exchangeable data. Not conditional on this window, "
        "and not valid under distribution shift."
    )

    @property
    def width(self) -> float:
        return self.upper - self.lower

    def covers(self, value: float) -> bool:
        return self.lower <= value <= self.upper


@dataclass
class SplitConformal:
    """Symmetric split-conformal interval for a bounded [0, 1] target.

    Symmetric (rather than CQR / locally-weighted) because the target is a
    probability: the loss is absolute error on a scale where the answer cannot
    leave ``[0, 1]``, so an asymmetric method would spend its width on a bound
    that is already enforced. That is a judgement, and it is wrong if the target
    ever becomes unbounded.

    **Measured limitation - clipping costs coverage.** A large error quantile
    means a wide interval, and a wide interval is mostly clipped away at the
    ``[0, 1]`` bounds, which silently destroys width the calibration paid for. On
    a model with a 0.49 error quantile, the promise of 90% coverage delivered
    87.2% at zero shift and 82.5% at a 0.12 shift. The lesson is that "the model is
    bad so the interval is wide" is not a safety margin, and ``coverage_report``
    is the check that catches it. CQR would be the fix; it is not implemented, so
    this is a known gap rather than a solved problem.
    """

    coverage: float = COVERAGE_90
    scores: np.ndarray = field(default_factory=lambda: np.empty(0))
    quantile: float | None = None

    def fit(self, predictions: np.ndarray, truth: np.ndarray) -> SplitConformal:
        """Calibrate on held-out data. Never call this on the test split."""
        predictions = np.asarray(predictions, dtype=float)
        truth = np.asarray(truth, dtype=float)
        if predictions.shape != truth.shape:
            raise ValueError("predictions and truth must have the same shape")
        if predictions.size == 0:
            raise ValueError("at least one calibration observation is required")
        if predictions.min() < 0.0 or predictions.max() > 1.0:
            raise ValueError("calibration scores are only defined for targets in [0, 1]")
        self.scores = np.abs(truth - predictions)
        self.quantile = _conformal_quantile(self.scores, 1.0 - self.coverage)
        return self

    @property
    def is_fitted(self) -> bool:
        return self.quantile is not None

    def predict(self, prediction: float) -> ConformalInterval:
        if not self.is_fitted:
            raise ValueError("SplitConformal.predict called before fit")
        value = float(prediction)
        lower = value - float(self.quantile)
        upper = value + float(self.quantile)
        clipped = lower < 0.0 or upper > 1.0
        return ConformalInterval(
            lower=max(0.0, lower),
            upper=min(1.0, upper),
            nominal_coverage=self.coverage,
            calibration_size=int(self.scores.size),
            quantile=float(self.quantile or 0.0),
            clipped=clipped,
        )

    def predict_many(self, predictions: np.ndarray) -> list[ConformalInterval]:
        return [self.predict(value) for value in np.asarray(predictions, dtype=float)]


class MondrianConformal:
    """Per-group calibration, for when coverage genuinely varies by group.

    Marginal coverage can be satisfied while one horizon is badly under-covered
    and another is wildly over-covered. Calibrating per group fixes the
    *behaviour* at the cost of a wider interval per group, because each group
    gets its own - shorter - calibration set. The guarantee remains marginal
    within a group; it is never conditional on a feature value.
    """

    def __init__(self, coverage: float = COVERAGE_90, min_per_group: int = 8) -> None:
        self.coverage = coverage
        self.min_per_group = min_per_group
        self._groups: dict[str, SplitConformal] = {}

    def fit(
        self, groups: list[str], predictions: np.ndarray, truth: np.ndarray
    ) -> MondrianConformal:
        groups = [str(g) for g in groups]
        predictions = np.asarray(predictions, dtype=float)
        truth = np.asarray(truth, dtype=float)
        if not (len(groups) == predictions.size == truth.size):
            raise ValueError("groups, predictions and truth must be the same length")
        self._groups = {}
        for group in sorted(set(groups)):
            mask = np.array([g == group for g in groups])
            if int(mask.sum()) < self.min_per_group:
                # Too few to calibrate: fall back to the pooled fit rather than
                # emitting a group-specific interval nobody can vouch for.
                continue
            self._groups[group] = SplitConformal(self.coverage).fit(predictions[mask], truth[mask])
        if not self._groups:
            raise InsufficientCalibrationData(
                f"every group has fewer than {self.min_per_group} calibration points"
            )
        self._pooled = SplitConformal(self.coverage).fit(predictions, truth)
        return self

    @property
    def groups(self) -> tuple[str, ...]:
        return tuple(sorted(self._groups))

    def predict(self, group: str, prediction: float) -> ConformalInterval:
        model = self._groups.get(str(group), self._pooled)
        interval = model.predict(prediction)
        if str(group) in self._groups:
            return interval
        return ConformalInterval(
            lower=interval.lower,
            upper=interval.upper,
            nominal_coverage=self.coverage,
            method="split-conformal-pooled-fallback",
            calibration_size=interval.calibration_size,
            quantile=interval.quantile,
            clipped=interval.clipped,
        )

    @property
    def is_fitted(self) -> bool:
        return bool(self._groups)


@dataclass
class HorizonCalibrator:
    """Per-horizon conformal bands, serializable alongside a trained model.

    Stored on the artifact rather than recomputed at inference, because the
    calibration split is gone by then and refitting on whatever data happens to
    be available at prediction time would quietly void the guarantee. An artifact
    with no calibrator produces ``None`` intervals, which is the honest state for
    a model that was never calibrated.
    """

    conformal_version: str = CONFORMAL_VERSION
    coverage: float = COVERAGE_90
    quantiles: dict[str, float] = field(default_factory=dict)
    calibration_sizes: dict[str, int] = field(default_factory=dict)
    pooled_quantile: float | None = None
    pooled_size: int = 0

    @classmethod
    def fit(
        cls,
        groups: list[str],
        predictions: np.ndarray,
        truth: np.ndarray,
        *,
        coverage: float = COVERAGE_90,
        pooled: SplitConformal | None = None,
    ) -> HorizonCalibrator:
        """Calibrate each group separately, with a pooled fallback.

        Per-group calibration is what stops a long horizon's wide error from being
        hidden by a short horizon's tight one under a single marginal promise.
        """
        predictions = np.asarray(predictions, dtype=float)
        truth = np.asarray(truth, dtype=float)
        groups = [str(g) for g in groups]
        if not (len(groups) == predictions.size == truth.size):
            raise ValueError("groups, predictions and truth must be the same length")
        quantiles: dict[str, float] = {}
        sizes: dict[str, int] = {}
        for group in sorted(set(groups)):
            mask = np.array([g == group for g in groups])
            scores = np.abs(truth[mask] - predictions[mask])
            try:
                quantiles[group] = _conformal_quantile(scores, 1.0 - coverage)
                sizes[group] = int(mask.sum())
            except InsufficientCalibrationData:
                # Too few points to promise this coverage for this horizon: leave
                # it to the pooled fit rather than publishing an interval that
                # cannot be justified.
                continue
        fallback = pooled or SplitConformal(coverage).fit(predictions, truth)
        return cls(
            coverage=coverage,
            quantiles=quantiles,
            calibration_sizes=sizes,
            pooled_quantile=float(fallback.quantile or 0.0),
            pooled_size=int(fallback.scores.size),
        )

    @property
    def horizons(self) -> tuple[str, ...]:
        return tuple(sorted(self.quantiles))

    @property
    def is_fitted(self) -> bool:
        return self.pooled_quantile is not None

    def predict_for_horizon(self, horizon: int, proba: float) -> ConformalInterval:
        key = str(horizon)
        if key in self.quantiles:
            return self._band(key, proba, self.quantiles[key], "split-conformal-mondrian")
        if self.pooled_quantile is None:
            raise ValueError("HorizonCalibrator has no calibration data")
        return self._band(key, proba, self.pooled_quantile, "split-conformal-pooled-fallback")

    def _band(self, key: str, proba: float, quantile: float, method: str) -> ConformalInterval:
        lower = max(0.0, proba - quantile)
        upper = min(1.0, proba + quantile)
        return ConformalInterval(
            lower=lower,
            upper=upper,
            nominal_coverage=self.coverage,
            method=method,
            calibration_size=self.calibration_sizes.get(key, self.pooled_size),
            quantile=quantile,
            clipped=proba - quantile < 0.0 or proba + quantile > 1.0,
        )

    def to_payload(self) -> dict:
        return {
            "conformal_version": self.conformal_version,
            "coverage": self.coverage,
            "quantiles": self.quantiles,
            "calibration_sizes": self.calibration_sizes,
            "pooled_quantile": self.pooled_quantile,
            "pooled_size": self.pooled_size,
        }

    @classmethod
    def from_payload(cls, payload: dict) -> HorizonCalibrator:
        if payload.get("conformal_version") != CONFORMAL_VERSION:
            raise ValueError(
                f"conformal payload version {payload.get('conformal_version')!r} cannot be "
                f"read by {CONFORMAL_VERSION!r}; refit the calibrator"
            )
        return cls(
            coverage=float(payload.get("coverage", COVERAGE_90)),
            quantiles={str(k): float(v) for k, v in (payload.get("quantiles") or {}).items()},
            calibration_sizes={
                str(k): int(v) for k, v in (payload.get("calibration_sizes") or {}).items()
            },
            pooled_quantile=(
                float(payload["pooled_quantile"])
                if payload.get("pooled_quantile") is not None
                else None
            ),
            pooled_size=int(payload.get("pooled_size", 0)),
        )


def _conformal_quantile(scores: np.ndarray, alpha: float) -> float:
    """The ``ceil((n+1)(1-alpha))``-th smallest score, with no clamping.

    When that index exceeds ``n`` the requested coverage cannot be delivered
    from this calibration set - typically because ``alpha`` is too small for the
    sample size. Clamping to the maximum score would return a *valid* interval
    that is silently narrower than promised, so this raises instead.
    """
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be strictly between 0 and 1")
    n = int(np.asarray(scores).size)
    if n == 0:
        raise ValueError("at least one calibration score is required")
    rank = math.ceil((n + 1) * (1.0 - alpha))
    if rank > n:
        raise InsufficientCalibrationData(
            f"cannot guarantee {1.0 - alpha:.1%} coverage from {n} calibration points: "
            f"needs at least {rank}. Use a lower coverage, or more calibration data."
        )
    return float(np.sort(np.asarray(scores, dtype=float))[rank - 1])


@dataclass(frozen=True)
class CoverageResult:
    """What actually happened, against what was promised."""

    nominal_coverage: float
    empirical_coverage: float | None
    n: int
    covered: int
    mean_width: float | None
    per_group: dict[str, float] = field(default_factory=dict)
    under_covers: bool = False
    note: str = ""


def coverage_report(
    intervals: list[ConformalInterval],
    truth: np.ndarray,
    *,
    groups: list[str] | None = None,
    tolerance: float | None = None,
) -> CoverageResult:
    """Measure the guarantee, so "it is conformal" is not the only claim.

    ``under_covers`` is the whole point. A conformal method that has never been
    shown to fail is not known to work; this is the check that distinguishes a
    guarantee that holds from a method that merely usually behaves.

    ``tolerance`` defaults to three binomial standard errors at the observed
    sample size. A fixed slack is wrong at both ends: too tight for a few hundred
    windows, where a *correct* method varies by 3% between runs, and too loose for
    tens of thousands. The guarantee holds over calibration draws, not over one
    realised calibration set, so this slack is not a weakening - it is the
    difference between measuring the method and measuring one run of it.
    """
    values = np.asarray(truth, dtype=float)
    if len(intervals) != values.size:
        raise ValueError("one interval per observation is required")
    hits = np.array(
        [interval.covers(float(v)) for interval, v in zip(intervals, values, strict=True)]
    )
    covered = int(hits.sum())
    empirical = covered / values.size if values.size else None
    nominal = intervals[0].nominal_coverage if intervals else 0.0
    if tolerance is None:
        standard_error = math.sqrt(max(nominal * (1.0 - nominal), 1e-9) / max(values.size, 1))
        tolerance = 3.0 * standard_error
    per_group: dict[str, float] = {}
    if groups is not None:
        if len(groups) != values.size:
            raise ValueError("groups must align with truth")
        for group in sorted(set(groups)):
            mask = np.array([g == group for g in groups])
            per_group[group] = float(hits[mask].mean()) if mask.any() else 0.0
    under = empirical is not None and empirical < nominal - tolerance
    return CoverageResult(
        nominal_coverage=nominal,
        empirical_coverage=empirical,
        n=int(values.size),
        covered=covered,
        mean_width=float(np.mean([i.width for i in intervals])) if intervals else None,
        per_group=per_group,
        under_covers=under,
        note=(
            f"Under-coverage beyond sampling slack: empirical {empirical:.4f} against "
            f"nominal {nominal:.2f}, tolerance {tolerance:.4f}. The data is probably not "
            "exchangeable with the calibration split, or the interval was fitted on "
            "the wrong split."
            if under
            else ""
        ),
    )


def reliability_table(
    probabilities: np.ndarray, truth: np.ndarray, bins: int = 10
) -> list[dict[str, float | int | None]]:
    """Binned predicted-vs-observed frequency, for a reliability diagram.

    Returns the raw material for the plot rather than a picture, so the numbers
    can be asserted on and quoted in a document. An empty bin reports ``None``,
    never 0.0: "no data here" is not "never correct here".
    """
    probabilities = np.asarray(probabilities, dtype=float)
    truth = np.asarray(truth, dtype=float)
    if probabilities.shape != truth.shape:
        raise ValueError("probabilities and truth must have the same shape")
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows: list[dict[str, float | int | None]] = []
    for index in range(bins):
        low, high = float(edges[index]), float(edges[index + 1])
        # The last bin is closed on the right so p == 1.0 is counted, not dropped.
        mask = (probabilities >= low) & (
            probabilities <= high if index == bins - 1 else probabilities < high
        )
        count = int(mask.sum())
        rows.append(
            {
                "bin_low": low,
                "bin_high": high,
                "count": count,
                "mean_predicted": float(probabilities[mask].mean()) if count else None,
                "observed_frequency": float(truth[mask].mean()) if count else None,
                "gap": (float(truth[mask].mean() - probabilities[mask].mean()) if count else None),
            }
        )
    return rows


def expected_calibration_error(
    probabilities: np.ndarray, truth: np.ndarray, bins: int = 10
) -> float:
    """Sample-weighted mean absolute gap between confidence and accuracy."""
    rows = reliability_table(probabilities, truth, bins=bins)
    total = sum(int(row["count"]) for row in rows)
    if total == 0:
        return 0.0
    weighted = sum(
        abs(float(row["gap"])) * int(row["count"])
        for row in rows
        if row["count"] and row["gap"] is not None
    )
    return weighted / total


def brier_decomposition(
    probabilities: np.ndarray, truth: np.ndarray, bins: int = 10
) -> dict[str, float]:
    """Split the Brier score into reliability, resolution and base rate.

    This is the diagnostic that distinguishes "the probabilities are wrong" from
    "the predictions carry no information". A model with resolution 0.0 and
    excellent reliability is confidently constant, which is worse than a noisy
    but informative model - and only the decomposition shows which one you have.
    """
    probabilities = np.asarray(probabilities, dtype=float)
    truth = np.asarray(truth, dtype=float)
    if probabilities.shape != truth.shape or probabilities.size == 0:
        raise ValueError("aligned, non-empty probabilities and truth are required")
    brier = float(np.mean((probabilities - truth) ** 2))
    base_rate = float(truth.mean())
    uncertainty = base_rate * (1.0 - base_rate)

    rows = reliability_table(probabilities, truth, bins=bins)
    reliability = 0.0
    resolution = 0.0
    for row in rows:
        count = int(row["count"])
        if not count or row["observed_frequency"] is None:
            continue
        weight = count / probabilities.size
        reliability += (
            weight * (float(row["observed_frequency"]) - float(row["mean_predicted"])) ** 2
        )
        resolution += weight * (float(row["observed_frequency"]) - base_rate) ** 2
    return {
        "brier": brier,
        "reliability": reliability,
        "resolution": resolution,
        "uncertainty": uncertainty,
        "base_rate": base_rate,
        # Murphy decomposition: Brier = reliability - resolution + uncertainty.
        "brier_from_decomposition": reliability - resolution + uncertainty,
        "skill_vs_base_rate": 1.0 - (brier / uncertainty) if uncertainty > 0 else 0.0,
    }


def interval_kind(interval: ConformalInterval) -> Literal["point", "interval", "degenerate"]:
    """How much the interval actually says, for honest reporting."""
    if interval.width <= 0.0:
        return "degenerate"
    if interval.upper >= 1.0 and interval.lower <= 0.0:
        return "degenerate"
    return "interval"


__all__ = [
    "COVERAGE_90",
    "COVERAGE_95",
    "COVERAGE_99",
    "CONFORMAL_VERSION",
    "PUBLISHABLE_COVERAGE",
    "ConformalInterval",
    "CoverageResult",
    "HorizonCalibrator",
    "InsufficientCalibrationData",
    "MondrianConformal",
    "SplitConformal",
    "brier_decomposition",
    "expected_calibration_error",
    "interval_kind",
    "reliability_table",
]
