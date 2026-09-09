"""Binary classification metrics with explicit handling of degenerate cases."""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel, ConfigDict, Field
from sklearn.metrics import average_precision_score


class ConfusionCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_negative: int = Field(ge=0)


class BinaryMetrics(BaseModel):
    """Mandatory baseline metrics; ``None`` means the metric is undefined for this data."""

    model_config = ConfigDict(extra="forbid")

    sample_count: int = Field(ge=0)
    positive_count: int = Field(ge=0)
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    pr_auc: float | None
    counts: ConfusionCounts


def compute_binary_metrics(
    y_true: np.ndarray,
    y_score: np.ndarray,
    *,
    threshold: float,
) -> BinaryMetrics:
    """Compute precision, recall, F1, FPR and PR-AUC at a fixed decision threshold."""
    truth = np.asarray(y_true, dtype=bool)
    scores = np.asarray(y_score, dtype=float)
    if truth.shape != scores.shape:
        raise ValueError("y_true and y_score must have the same shape")
    if not 0 < threshold < 1:
        raise ValueError("threshold must be strictly between zero and one")

    predicted = scores >= threshold
    tp = int(np.sum(predicted & truth))
    fp = int(np.sum(predicted & ~truth))
    tn = int(np.sum(~predicted & ~truth))
    fn = int(np.sum(~predicted & truth))

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    elif precision is not None and recall is not None:
        f1 = 0.0

    positives = int(truth.sum())
    pr_auc = None
    if 0 < positives < truth.size:
        pr_auc = float(average_precision_score(truth, scores))

    return BinaryMetrics(
        sample_count=int(truth.size),
        positive_count=positives,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=_ratio(fp, fp + tn),
        pr_auc=pr_auc,
        counts=ConfusionCounts(
            true_positive=tp, false_positive=fp, true_negative=tn, false_negative=fn
        ),
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    value = numerator / denominator
    return value if math.isfinite(value) else None
