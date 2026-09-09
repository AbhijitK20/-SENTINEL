"""Leakage-safe decision-threshold calibration on validation data.

The shipped decision threshold (0.5) is a default, not a tuned value. This
module selects a threshold from a fixed grid using validation-split
probabilities only — never test data — and records every candidate so the
choice is auditable. Selection objectives:

- ``f1``: maximize F1 on the validation split.
- ``youden``: maximize recall − false-positive rate (sensitivity +
  specificity − 1), which favors earlier warning at controlled false alarms.

Ties are resolved toward the *lowest* threshold: among equally good
candidates the earlier warning is preferred for a forecasting product. The
result records the rule so the choice is reproducible.
"""

from __future__ import annotations

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from trajectory.metrics import compute_binary_metrics

CALIBRATION_VERSION = "threshold-calibration-v1"
DEFAULT_THRESHOLD = 0.5
OBJECTIVES = ("f1", "youden")


class ThresholdCandidate(BaseModel):
    """Metrics at one candidate threshold on the validation split."""

    model_config = ConfigDict(extra="forbid")

    threshold: float = Field(gt=0.0, lt=1.0)
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    false_positive_rate: float | None = None
    objective_value: float


class CalibrationResult(BaseModel):
    """Auditable outcome of threshold selection on validation data."""

    model_config = ConfigDict(extra="forbid")

    calibration_version: str = CALIBRATION_VERSION
    objective: str
    best_threshold: float = Field(gt=0.0, lt=1.0)
    default_threshold: float = DEFAULT_THRESHOLD
    tie_rule: str = "lowest threshold among ties (earlier warning preferred)"
    candidates: list[ThresholdCandidate]
    sample_count: int = Field(ge=0)
    positive_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)


def calibrate_threshold(
    probabilities: list[float] | np.ndarray,
    labels: list[bool] | np.ndarray,
    *,
    objective: str = "f1",
    grid: list[float] | np.ndarray | None = None,
) -> CalibrationResult:
    """Select a decision threshold from a fixed grid on validation data."""
    scores = np.asarray(probabilities, dtype=float)
    truth = np.asarray(labels, dtype=bool)
    if scores.shape != truth.shape:
        raise ValueError("probabilities and labels must have the same shape")
    if scores.size == 0:
        raise ValueError("at least one validation sample is required")
    if objective not in OBJECTIVES:
        raise ValueError(f"objective must be one of {OBJECTIVES}")

    warnings: list[str] = []
    positives = int(truth.sum())
    if positives == 0 or positives == truth.size:
        warnings.append(
            "Validation split is single-class; calibration is degenerate and "
            f"the default threshold {DEFAULT_THRESHOLD} is returned."
        )
        return CalibrationResult(
            objective=objective,
            best_threshold=DEFAULT_THRESHOLD,
            candidates=[],
            sample_count=int(truth.size),
            positive_count=positives,
            warnings=warnings,
        )

    if grid is None:
        grid = np.round(np.arange(0.05, 0.96, 0.05), 2)
    grid = np.asarray(grid, dtype=float)
    if grid.size == 0 or grid.min() <= 0 or grid.max() >= 1:
        raise ValueError("grid values must lie strictly between zero and one")

    candidates: list[ThresholdCandidate] = []
    for threshold in grid:
        metrics = compute_binary_metrics(truth, scores, threshold=float(threshold))
        if objective == "f1":
            value = metrics.f1 if metrics.f1 is not None else 0.0
        else:
            recall = metrics.recall if metrics.recall is not None else 0.0
            fpr = metrics.false_positive_rate if metrics.false_positive_rate is not None else 0.0
            value = recall - fpr
        candidates.append(
            ThresholdCandidate(
                threshold=float(threshold),
                precision=metrics.precision,
                recall=metrics.recall,
                f1=metrics.f1,
                false_positive_rate=metrics.false_positive_rate,
                objective_value=float(value),
            )
        )

    best_value = max(candidate.objective_value for candidate in candidates)
    best_threshold = min(
        candidate.threshold for candidate in candidates if candidate.objective_value == best_value
    )

    return CalibrationResult(
        objective=objective,
        best_threshold=float(best_threshold),
        candidates=candidates,
        sample_count=int(truth.size),
        positive_count=positives,
        warnings=warnings,
    )


__all__ = [
    "CALIBRATION_VERSION",
    "DEFAULT_THRESHOLD",
    "OBJECTIVES",
    "CalibrationResult",
    "ThresholdCandidate",
    "calibrate_threshold",
]
