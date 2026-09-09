import numpy as np
import pytest

from trajectory.metrics import compute_binary_metrics


def test_metrics_match_hand_computed_confusion_matrix() -> None:
    truth = np.array([1, 1, 1, 0, 0, 0, 0, 0])
    scores = np.array([0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.1, 0.1])

    metrics = compute_binary_metrics(truth, scores, threshold=0.5)

    assert metrics.counts.model_dump() == {
        "true_positive": 2,
        "false_positive": 1,
        "true_negative": 4,
        "false_negative": 1,
    }
    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.recall == pytest.approx(2 / 3)
    assert metrics.f1 == pytest.approx(2 / 3)
    assert metrics.false_positive_rate == pytest.approx(0.2)
    assert metrics.pr_auc is not None and 0 < metrics.pr_auc <= 1


def test_undefined_metrics_are_reported_as_none_not_zero() -> None:
    truth = np.array([0, 0, 0])
    scores = np.array([0.1, 0.2, 0.3])

    metrics = compute_binary_metrics(truth, scores, threshold=0.5)

    assert metrics.precision is None  # no predicted positives
    assert metrics.recall is None  # no actual positives
    assert metrics.f1 is None
    assert metrics.pr_auc is None
    assert metrics.false_positive_rate == 0.0


def test_invalid_inputs_are_rejected() -> None:
    with pytest.raises(ValueError, match="same shape"):
        compute_binary_metrics(np.array([1, 0]), np.array([0.5]), threshold=0.5)
    with pytest.raises(ValueError, match="threshold"):
        compute_binary_metrics(np.array([1, 0]), np.array([0.5, 0.5]), threshold=1.0)
