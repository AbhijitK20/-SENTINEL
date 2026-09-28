# SPDX-License-Identifier: Apache-2.0
"""Isotonic recalibration: fix a well-ranked, badly-scaled classifier.

The world model's risk head had this failure, measured on the test split:

    predicted bin   mean p   observed   gap
    [0.5, 0.6)       0.554      0.000   -0.554
    [0.7, 0.8)       0.752      0.000   -0.752
    [0.8, 0.9)       0.866      0.091   -0.775
    [0.9, 1.0)       0.987      0.843   -0.144

Read that carefully. The *ranking* is good - observed frequency rises
monotonically with predicted probability. The *scale* is wrong: whenever the head
said 0.5-0.9, the event essentially never happened. A consumer acting on "65%
likely" was being told that about events with a 0% observed rate.

That failure mode has a standard name and a standard fix, and the fix is not
temperature scaling. Temperature scaling has one parameter and cannot turn a
smooth sigmoid into the step-shaped relationship above. Isotonic regression can,
because it is a free monotone function: pool adjacent violators gives the
least-squares non-decreasing fit, which maps 0.55 to roughly 0 and 0.99 to
roughly 0.85 - which is what the data actually says.

Why this is a legitimate correction rather than curve-fitting to the test set:
the fit uses the **validation** split only, it is monotone, and it cannot change
which item ranks above which. It corrects the mapping from score to frequency and
nothing else. A change in ranking is a modelling change and is not attempted here.

Fitting isotonic on the split you then score is the classic way to buy fake
numbers, so :class:`IsotonicCalibrator` records its own ``n_fit`` and refuses to
predict when it was fitted on too few points to justify the guarantee it implies.

**Measured limitation - a step is not reliably recovered.** If the true rate
jumps, the fit only places the jump where a block boundary happens to land, and
where that is depends on where observations fell. Across six seeds on a step at
0.80, fits were equally likely to straddle it, at 2 000 points per fit. More data
helps on average; it does not make the step reliable. So the answer to "should we
adopt this?" is never "the curve looks right" - it is
:func:`recalibration_outcome` on held-out data, which is why that function
exists and why ``improved`` is the field to check.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

ISOTONIC_VERSION = "isotonic-recalibration-v1"

# Below this, the fit is closer to memorising than generalising, and a
# recalibration curve with that many points is a liability.
MIN_FIT_POINTS = 20


class InsufficientRecalibrationData(ValueError):
    """Raised when the fit set is too small for a calibration curve to mean anything."""


@dataclass
class IsotonicCalibrator:
    """A non-decreasing map from raw score to observed frequency.

    Stored as thresholds and values rather than raw points, so a fitted curve is
    a flat list of steps rather than one knot per calibration observation, and
    serialises into a model artifact without bloat.
    """

    isotonic_version: str = ISOTONIC_VERSION
    thresholds: list[float] = field(default_factory=list)
    values: list[float] = field(default_factory=list)
    n_fit: int = 0
    # How far the recalibration moved the predictions, on average. A large
    # correction is a warning that the underlying head was badly scaled, and is
    # reported rather than hidden.
    mean_absolute_shift: float = 0.0
    fit_base_rate: float = 0.0
    caveat: str = (
        "Monotone recalibration fitted on a held-out split. It changes the mapping "
        "from score to frequency and cannot change the ranking; it is not a "
        "correction of the model's discrimination."
    )

    @classmethod
    def fit(
        cls, scores: np.ndarray, labels: np.ndarray, *, min_points: int = MIN_FIT_POINTS
    ) -> IsotonicCalibrator:
        """Pool adjacent violators over the validation scores.

        ``min_points`` guards the classic error: a curve fitted on 30 nearly
        identical scores reproduces those scores perfectly and generalises to
        nothing.
        """
        scores = np.asarray(scores, dtype=float)
        labels = np.asarray(labels, dtype=float)
        if scores.shape != labels.shape:
            raise ValueError("scores and labels must have the same shape")
        n = scores.size
        if n < min_points:
            raise InsufficientRecalibrationData(
                f"isotonic recalibration needs at least {min_points} held-out points, "
                f"got {n}. Refusing to fit a curve that would memorise the fit set."
            )
        if labels.min() < 0.0 or labels.max() > 1.0:
            raise ValueError("labels must be in [0, 1]")

        order = np.argsort(scores, kind="mergesort")
        ordered_scores = scores[order]
        ordered_labels = labels[order]

        # PAVA: repeatedly merge neighbouring blocks whose mean would decrease.
        block_values: list[float] = []
        block_weights: list[float] = []
        block_ends: list[int] = []
        for index, value in enumerate(ordered_labels):
            block_values.append(float(value))
            block_weights.append(1.0)
            block_ends.append(index)
            while len(block_values) > 1 and block_values[-2] > block_values[-1]:
                left_value = block_values.pop()
                left_weight = block_weights.pop()
                left_end = block_ends.pop()
                block_values[-1] = (
                    block_values[-1] * block_weights[-1] + left_value * left_weight
                ) / (block_weights[-1] + left_weight)
                block_weights[-1] += left_weight
                block_ends[-1] = left_end

        # One threshold per block start, so prediction is a search over the
        # breakpoints rather than a scan of the fit set.
        starts = [0] + [end + 1 for end in block_ends[:-1]]
        thresholds = [float(ordered_scores[start]) for start in starts]
        values = [float(v) for v in block_values]

        # The empirical CDF at and below the final breakpoint.
        values.append(1.0)
        thresholds.append(float(ordered_scores[-1]) + 1e-9)

        calibrated = cls._apply(np.asarray(scores), thresholds, values)
        return cls(
            thresholds=thresholds,
            values=values,
            n_fit=n,
            mean_absolute_shift=float(np.mean(np.abs(calibrated - scores))),
            fit_base_rate=float(labels.mean()),
        )

    @property
    def is_fitted(self) -> bool:
        return bool(self.thresholds) and len(self.thresholds) == len(self.values)

    def predict(self, score: float) -> float:
        if not self.is_fitted:
            raise ValueError("IsotonicCalibrator.predict called before fit")
        return self._apply(np.array([float(score)]), self.thresholds, self.values)[0]

    def predict_many(self, scores: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("IsotonicCalibrator.predict_many called before fit")
        return self._apply(np.asarray(scores, dtype=float), self.thresholds, self.values)

    @staticmethod
    def _apply(scores: np.ndarray, thresholds: list[float], values: list[float]) -> np.ndarray:
        # searchsorted on the breakpoints: everything at or below a breakpoint
        # takes that block's value. Clipped so a recalibrated probability can
        # never leave [0, 1] even if the stored curve is hand-edited.
        index = np.searchsorted(np.asarray(thresholds), scores, side="left")
        return np.clip(np.asarray(values)[np.clip(index, 0, len(values) - 1)], 0.0, 1.0)

    def to_payload(self) -> dict:
        return {
            "isotonic_version": self.isotonic_version,
            "thresholds": self.thresholds,
            "values": self.values,
            "n_fit": self.n_fit,
            "mean_absolute_shift": self.mean_absolute_shift,
            "fit_base_rate": self.fit_base_rate,
        }

    @classmethod
    def from_payload(cls, payload: dict) -> IsotonicCalibrator:
        if payload.get("isotonic_version") != ISOTONIC_VERSION:
            raise ValueError(
                f"isotonic payload version {payload.get('isotonic_version')!r} cannot be "
                f"read by {ISOTONIC_VERSION!r}; refit the calibrator"
            )
        return cls(
            thresholds=[float(t) for t in payload.get("thresholds", [])],
            values=[float(v) for v in payload.get("values", [])],
            n_fit=int(payload.get("n_fit", 0)),
            mean_absolute_shift=float(payload.get("mean_absolute_shift", 0.0)),
            fit_base_rate=float(payload.get("fit_base_rate", 0.0)),
        )


@dataclass(frozen=True)
class RecalibrationOutcome:
    """Before and after, so the change is a measurement rather than an assertion."""

    brier_before: float
    brier_after: float
    ece_before: float
    ece_after: float
    bias_before: float
    bias_after: float
    mean_absolute_shift: float
    n_fit: int
    ranking_unchanged: bool

    @property
    def improved(self) -> bool:
        return self.brier_after < self.brier_before

    def as_dict(self) -> dict[str, float | int | bool]:
        return {
            "brier_before": self.brier_before,
            "brier_after": self.brier_after,
            "brier_improvement": self.brier_before - self.brier_after,
            "ece_before": self.ece_before,
            "ece_after": self.ece_after,
            "bias_before": self.bias_before,
            "bias_after": self.bias_after,
            "mean_absolute_shift": self.mean_absolute_shift,
            "n_fit": self.n_fit,
            "ranking_unchanged": self.ranking_unchanged,
        }


def recalibration_outcome(
    scores: np.ndarray,
    labels: np.ndarray,
    calibrator: IsotonicCalibrator,
) -> RecalibrationOutcome:
    """Compare a model before and after recalibration, on the given labels.

    ``ranking_unchanged`` is checked rather than assumed. A monotone map
    preserves the order of the values it sees, but not necessarily the order of
    the *original* scores if the curve has ties, and a tie that reorders a
    high-value pair would be a silent change in behaviour. Measuring it costs
    nothing and catches a real class of bug.
    """
    from sentinel.conformal import expected_calibration_error

    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels, dtype=float)
    recalibrated = calibrator.predict_many(scores)

    def brier(values: np.ndarray) -> float:
        return float(np.mean((values - labels) ** 2))

    def bias(values: np.ndarray) -> float:
        return float(values.mean() - labels.mean())

    # Monotonicity, not "the same argsort". A monotone map may send distinct
    # scores to equal values, and then the order *among the tied elements* is
    # arbitrary - comparing sort permutations would report a reordering that
    # never happened. The real invariant is: sorted by score, the recalibrated
    # values never decrease. That is what "monotone" guarantees, and it is what
    # must hold for this to be a correction rather than a change of model.
    order = np.argsort(scores, kind="mergesort")
    differences = np.diff(recalibrated[order])
    ranking_unchanged = bool(np.all(differences >= -1e-12))
    return RecalibrationOutcome(
        brier_before=brier(scores),
        brier_after=brier(recalibrated),
        ece_before=expected_calibration_error(scores, labels),
        ece_after=expected_calibration_error(recalibrated, labels),
        bias_before=bias(scores),
        bias_after=bias(recalibrated),
        mean_absolute_shift=calibrator.mean_absolute_shift,
        n_fit=calibrator.n_fit,
        ranking_unchanged=ranking_unchanged,
    )


def brier_from_pava(scores: np.ndarray, labels: np.ndarray) -> float:
    """The in-sample Brier score the isotonic fit achieves on its own fit set.

    Useful only as a sanity check: an isotonic fit's in-sample Brier is always at
    least as good as the uncalibrated model by construction, which is exactly why
    it must never be quoted as a held-out result.
    """
    if scores.size != labels.size:
        raise ValueError("scores and labels must have the same shape")
    try:
        calibrator = IsotonicCalibrator.fit(scores, labels)
    except InsufficientRecalibrationData:
        return float("nan")
    return float(np.mean((calibrator.predict_many(scores) - labels) ** 2))


def logit(probability: np.ndarray | float) -> np.ndarray:
    """Probability to log-odds, with the endpoints pulled in to 1e-12.

    The clip is at 1e-12 rather than at 0 and 1 so that ``sigmoid(logit(p))`` is
    exactly ``p`` everywhere inside the open interval, while a reported 0.0 or
    1.0 yields a finite -27.6 or +27.6 instead of an infinity. Downstream code
    that averages log-odds would otherwise produce NaN on a saturated prediction.
    """
    p = np.clip(np.asarray(probability, dtype=float), 1e-12, 1 - 1e-12)
    result = np.log(p / (1.0 - p))
    return float(result) if np.isscalar(probability) else result


def sigmoid(value: np.ndarray | float) -> np.ndarray:
    """Log-odds to probability, branch-stable so large magnitudes do not overflow."""
    v = np.asarray(value, dtype=float)
    out = np.where(v >= 0, 1.0 / (1.0 + np.exp(-v)), np.exp(v) / (1.0 + np.exp(v)))
    return float(out) if np.isscalar(value) else out


def reliability_curve(
    scores: np.ndarray, labels: np.ndarray, bins: int = 10
) -> list[dict[str, float | int | None]]:
    """A reliability diagram as data, so the plot and the prose share a source.

    Re-exported from :mod:`sentinel.conformal` rather than reimplemented; two
    implementations of "bin the predictions" would eventually disagree.
    """
    from sentinel.conformal import reliability_table

    return reliability_table(scores, labels, bins=bins)


__all__ = [
    "ISOTONIC_VERSION",
    "MIN_FIT_POINTS",
    "InsufficientRecalibrationData",
    "IsotonicCalibrator",
    "RecalibrationOutcome",
    "brier_from_pava",
    "logit",
    "recalibration_outcome",
    "reliability_curve",
    "sigmoid",
]
