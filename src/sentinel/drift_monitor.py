# SPDX-License-Identifier: Apache-2.0
"""A drift monitor with a trip point that means something, and a measured delay.

:mod:`sentinel.drift` ships a PSI statistic and bands it at hardcoded 0.10 and
0.25. Those numbers are the industry default and are quoted without the sample
size that produces them, which makes them unfalsifiable: nothing in the codebase
can say what false-alarm rate they correspond to. This module answers that by
calibrating the trip point against the data's own null, and it reuses the shipped
``psi`` rather than adding a second implementation.

Three things have to be true for a drift alarm to mean anything, and each was
wrong in a first attempt:

1. **One threshold, on the maximum across features.** Per-feature thresholds
   combined by taking the max is not a 1% alarm rate over 98 features, it is
   about 63%. Calibrating the max-statistic is the only way the level means what
   it says.
2. **Blocks of the size actually scored.** PSI depends on sample size. A
   ten-window verdict lies almost entirely inside one scenario, so the statistic
   ends up measuring *which scenario it is looking at* rather than whether the
   process changed, and a 99% threshold fired on a quarter of held-out benign
   windows.
3. **A control disjoint from the calibration.** Scoring the reference windows back
   through a monitor whose bin edges were estimated from those same windows
   reports a false-alarm rate several times better than the monitor can deliver.
   That mistake was in the first version of the report script.

What the experiment finds is in ``docs/KNOWN_LIMITATIONS.md``. In short: on this
data the false-alarm rate before a shift is as high as the detection rate after
it, so the monitor is a tripwire to investigate and not an alarm to page on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from sentinel.drift import PSI_BINS, psi

DRIFT_MONITOR_VERSION = "drift-monitor-v1"

DEFAULT_WINDOW = 30
# Blocks the aggregation is swept over. Reported whole rather than tuned.
WINDOW_SWEEP = (10, 30, 60, 120)


@dataclass
class DriftVerdict:
    """One block's reading, with enough context to argue with."""

    index: int
    psi: float
    threshold: float
    feature: str
    exceeded: bool

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "psi": round(self.psi, 6),
            "threshold": round(self.threshold, 6),
            "feature": self.feature,
            "exceeded": self.exceeded,
        }


@dataclass
class DriftMonitor:
    """Watch a stream of windows against a reference, per feature.

    The threshold is one number: a quantile of the *maximum* PSI across features,
    measured on held-out windows from the same population as the reference. No
    literature constant is involved, because a constant borrowed from a paper is
    tuned to somebody else's sample size.
    """

    features: tuple[str, ...] = ()
    reference: dict[str, list[float]] = field(default_factory=dict)
    null_psi_max: list[float] = field(default_factory=list)
    threshold: float = 0.0
    n_null: int = 0
    level: float = 0.99
    window: int = DEFAULT_WINDOW
    bins: int = PSI_BINS

    @property
    def is_calibrated(self) -> bool:
        return bool(self.null_psi_max)

    def calibrate(
        self,
        reference: np.ndarray,
        names: list[str],
        null: np.ndarray,
        *,
        level: float = 0.99,
        window: int = DEFAULT_WINDOW,
        bins: int = PSI_BINS,
    ) -> DriftMonitor:
        """Fix the bin edges from ``reference`` and one trip point from ``null``.

        ``null`` must come from the same population as ``reference`` - later
        windows of the pre-shift period, or different scenarios of the same
        generator. A null drawn from the shifted data would calibrate the monitor
        to already be broken.
        """
        matrix = np.asarray(reference, dtype=float)
        null_matrix = np.asarray(null, dtype=float)
        if matrix.ndim != 2 or matrix.shape[1] != len(names):
            raise ValueError("one name is required per feature")
        if null_matrix.ndim != 2 or null_matrix.shape[1] != matrix.shape[1]:
            raise ValueError("null and reference must have the same features")
        if window < 1:
            raise ValueError("window must be at least one")
        if null_matrix.shape[0] < window:
            raise ValueError(
                f"need at least {window} null windows to form one block, got {null_matrix.shape[0]}"
            )
        if not 0.5 < level < 1.0:
            raise ValueError("level is a quantile of the null and must be in (0.5, 1)")
        self.features = tuple(names)
        self.reference = {name: matrix[:, i].tolist() for i, name in enumerate(names)}
        self.n_null = int(null_matrix.shape[0])
        self.level = level
        self.window = window
        self.bins = bins
        self.null_psi_max = [
            max(
                psi(self.reference[name], null_matrix[start:, column].tolist(), bins=bins)
                for name, column in zip(names, range(len(names)), strict=True)
            )
            for start in range(null_matrix.shape[0] - window + 1)
        ]
        self.threshold = float(np.quantile(self.null_psi_max, level))
        return self

    def check(self, block: np.ndarray) -> DriftVerdict:
        """Score one block; the verdict names the feature that moved most."""
        if not self.is_calibrated:
            raise ValueError("DriftMonitor.calibrate must run before check")
        chunk = np.asarray(block, dtype=float)
        if chunk.ndim != 2 or chunk.shape[1] != len(self.features):
            raise ValueError("block must be (n, n_features) matching the calibration")
        scores = {
            name: psi(self.reference[name], chunk[:, column].tolist(), bins=self.bins)
            for column, name in enumerate(self.features)
        }
        feature = max(scores, key=lambda k: scores[k])
        return DriftVerdict(
            index=0,
            psi=scores[feature],
            threshold=self.threshold,
            feature=feature,
            exceeded=scores[feature] > self.threshold,
        )

    def stream(self, windows: np.ndarray) -> list[DriftVerdict]:
        """Score a stream in order, one rolling block per starting position.

        The first ``window - 1`` positions produce no verdict: there is not enough
        history, and scoring a shorter block than the threshold was calibrated on
        would compare two different statistics.
        """
        matrix = np.asarray(windows, dtype=float)
        if matrix.ndim != 2 or matrix.shape[1] != len(self.features):
            raise ValueError("stream must be (n, n_features) matching the calibration")
        verdicts: list[DriftVerdict] = []
        for start in range(self.window - 1, matrix.shape[0]):
            verdict = self.check(matrix[start - self.window + 1 : start + 1])
            verdict.index = start
            verdicts.append(verdict)
        return verdicts

    def as_dict(self) -> dict:
        return {
            "version": DRIFT_MONITOR_VERSION,
            "n_features": len(self.features),
            "n_null_windows": self.n_null,
            "null_level": self.level,
            "rolling_window": self.window,
            "bins": self.bins,
            "threshold": round(self.threshold, 6),
            "null_psi_max_median": round(float(np.median(self.null_psi_max)), 6),
        }


@dataclass
class DetectionDelay:
    """Blocks between the shift starting and the monitor saying so."""

    delay_windows: int | None
    onset_index: int
    n_false_alarms: int
    n_windows: int
    feature: str | None
    note: str = ""

    @property
    def detected(self) -> bool:
        return self.delay_windows is not None

    def as_dict(self) -> dict:
        return {
            "delay_windows": self.delay_windows,
            "onset_index": self.onset_index,
            "n_false_alarms": self.n_false_alarms,
            "n_windows": self.n_windows,
            "feature": self.feature,
            "detected": self.detected,
            "note": self.note,
        }


def detection_delay(verdicts: list[DriftVerdict], onset_index: int) -> DetectionDelay:
    """Windows from ``onset_index`` to the first alarm at or after it.

    Alarms before the onset are counted rather than ignored: a monitor that fires
    constantly and one that fires once are different instruments, and reporting
    only the delay hides that.
    """
    if onset_index < 0:
        raise ValueError("onset_index cannot be negative")
    false_alarms = sum(1 for v in verdicts if v.index < onset_index and v.exceeded)
    for verdict in verdicts:
        if verdict.index >= onset_index and verdict.exceeded:
            return DetectionDelay(
                delay_windows=verdict.index - onset_index,
                onset_index=onset_index,
                n_false_alarms=false_alarms,
                n_windows=len(verdicts),
                feature=verdict.feature,
            )
    return DetectionDelay(
        delay_windows=None,
        onset_index=onset_index,
        n_false_alarms=false_alarms,
        n_windows=len(verdicts),
        feature=None,
        note="no block after the shift exceeded the threshold",
    )


@dataclass
class ShiftOutcome:
    """What a shift did to the model, the interval, and the monitor."""

    shift_name: str
    in_distribution: dict[str, float] = field(default_factory=dict)
    shifted: dict[str, float] = field(default_factory=dict)
    coverage_in_distribution: float | None = None
    coverage_shifted: float | None = None
    nominal_coverage: float | None = None
    delay: DetectionDelay | None = None
    false_alarms: int = 0
    control_windows: int = 0
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "version": DRIFT_MONITOR_VERSION,
            "shift": self.shift_name,
            "in_distribution": self.in_distribution,
            "shifted": self.shifted,
            "interval": {
                "nominal": self.nominal_coverage,
                "in_distribution": self.coverage_in_distribution,
                "shifted": self.coverage_shifted,
            },
            "detection": self.delay.as_dict() if self.delay else None,
            "false_alarms": self.false_alarms,
            "control_windows": self.control_windows,
            "note": self.note,
        }


def false_alarm_rate_at(
    reference: np.ndarray,
    names: list[str],
    control: np.ndarray,
    thresholds: tuple[float, ...],
    *,
    window: int = DEFAULT_WINDOW,
    bins: int = PSI_BINS,
) -> dict[float, float]:
    """What fraction of held-out blocks exceed each fixed PSI threshold.

    This is what makes :func:`sentinel.drift.band_of` falsifiable. The bands say
    "moderate" from 0.10 and "significant" from 0.25, and the API exposes them
    through ``/compare``, but no amount of reading the source tells you what
    false-alarm rate those numbers buy at a given block size. Measuring it here is
    the difference between a threshold and a claim.
    """
    columns = {
        name: np.asarray(reference, dtype=float)[:, index].tolist()
        for index, name in enumerate(names)
    }
    data = np.asarray(control, dtype=float)
    per_feature: list[list[float]] = [[] for _ in names]
    maxima: list[float] = []
    for start in range(data.shape[0] - window + 1):
        block = data[start : start + window]
        scores = [
            psi(columns[name], block[:, index].tolist(), bins=bins)
            for index, name in enumerate(names)
        ]
        for index, score in enumerate(scores):
            per_feature[index].append(score)
        maxima.append(max(scores))
    if not maxima:
        return {threshold: float("nan") for threshold in thresholds}
    result = {threshold: float(np.mean(np.asarray(maxima) > threshold)) for threshold in thresholds}
    # Also report the single-feature rate, because the gap between the two says
    # whether the constant is wrong or the aggregation is.
    for threshold in thresholds:
        rates = [float(np.mean(np.asarray(scores) > threshold)) for scores in per_feature]
        result[f"median_single_feature_at_{threshold}"] = float(np.median(rates))
    return result


def sweep_aggregation(
    reference: np.ndarray,
    names: list[str],
    null: np.ndarray,
    stream: np.ndarray,
    onset_index: int,
    windows: tuple[int, ...] = WINDOW_SWEEP,
    *,
    level: float = 0.99,
) -> list[dict]:
    """Measure the false-alarm/delay trade-off across block sizes.

    The whole curve is reported because picking the block size that happens to
    look best is how you end up calibrating on a zero false-alarm count over
    seventeen windows.
    """
    rows: list[dict] = []
    for window in windows:
        monitor = DriftMonitor().calibrate(reference, names, null, level=level, window=window)
        verdicts = monitor.stream(stream)
        delay = detection_delay(verdicts, onset_index)
        pre = [v for v in verdicts if v.index < onset_index]
        post = [v for v in verdicts if v.index >= onset_index]
        false_alarms = sum(1 for v in pre if v.exceeded)
        rows.append(
            {
                "rolling_window": window,
                "false_alarms_pre_shift": false_alarms,
                "pre_shift_windows": len(pre),
                "false_alarm_rate": false_alarms / max(1, len(pre)),
                "detections_post_shift": sum(1 for v in post if v.exceeded),
                "post_shift_windows": len(post),
                "delay_windows": delay.delay_windows,
                "detected": delay.detected,
                "feature": delay.feature,
                "threshold": round(monitor.threshold, 6),
            }
        )
    return rows


def describe(outcome: ShiftOutcome) -> str:
    """One paragraph stating what moved and what did not, with no adjectives."""
    parts = [
        f"Shift: {outcome.shift_name}.",
        "In distribution: "
        + ", ".join(f"{k} {v:.4f}" for k, v in sorted(outcome.in_distribution.items()))
        + ".",
        "After the shift: "
        + ", ".join(f"{k} {v:.4f}" for k, v in sorted(outcome.shifted.items()))
        + ".",
    ]
    if None not in (
        outcome.nominal_coverage,
        outcome.coverage_in_distribution,
        outcome.coverage_shifted,
    ):
        parts.append(
            f"Conformal coverage promised {outcome.nominal_coverage:.0%}, delivered "
            f"{outcome.coverage_in_distribution:.1%} before the shift and "
            f"{outcome.coverage_shifted:.1%} after it."
        )
    if outcome.delay is not None:
        if outcome.delay.detected:
            parts.append(
                f"The monitor tripped {outcome.delay.delay_windows} window(s) after the "
                f"shift began, on `{outcome.delay.feature}`."
            )
        else:
            parts.append(
                f"The monitor never tripped in {outcome.delay.n_windows} blocks after the shift."
            )
        parts.append(
            f"False alarms: {outcome.false_alarms} of {outcome.control_windows} blocks "
            "from a cohort disjoint from both the reference and the null."
        )
    if outcome.note:
        parts.append(outcome.note)
    return " ".join(parts)


__all__ = [
    "DEFAULT_WINDOW",
    "DRIFT_MONITOR_VERSION",
    "WINDOW_SWEEP",
    "DetectionDelay",
    "DriftMonitor",
    "DriftVerdict",
    "ShiftOutcome",
    "describe",
    "detection_delay",
    "false_alarm_rate_at",
    "sweep_aggregation",
]
