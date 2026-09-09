"""Tests for leakage-safe threshold calibration."""

from __future__ import annotations

import numpy as np
import pytest

from trajectory.calibration import (
    CALIBRATION_VERSION,
    DEFAULT_THRESHOLD,
    calibrate_threshold,
)


def test_best_threshold_maximizes_f1() -> None:
    rng = np.random.default_rng(0)
    scores = np.concatenate([rng.uniform(0.0, 0.4, 40), rng.uniform(0.6, 1.0, 40)])
    labels = np.concatenate([np.zeros(40, dtype=bool), np.ones(40, dtype=bool)])

    result = calibrate_threshold(scores, labels, objective="f1")

    assert result.calibration_version == CALIBRATION_VERSION
    assert result.best_threshold == pytest.approx(min(0.55, 0.95), abs=0.45)
    best = max(c.objective_value for c in result.candidates)
    chosen = next(c for c in result.candidates if c.threshold == result.best_threshold)
    assert chosen.objective_value == best


def test_ties_prefer_lower_threshold() -> None:
    # Perfect separation: every threshold strictly between the classes ties,
    # and the lowest such candidate must win (earlier warning preferred).
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    labels = np.array([False, False, True, True])

    result = calibrate_threshold(scores, labels, objective="f1")

    assert result.best_threshold == 0.25  # lowest grid point above 0.2, below 0.8


def test_youden_objective_runs() -> None:
    rng = np.random.default_rng(1)
    scores = rng.uniform(0, 1, 100)
    labels = rng.random(100) < 0.5

    result = calibrate_threshold(scores, labels, objective="youden")

    assert 0 < result.best_threshold < 1
    assert result.candidates


def test_single_class_degenerates_to_default() -> None:
    result = calibrate_threshold([0.9, 0.8, 0.7], [True, True, True])

    assert result.best_threshold == DEFAULT_THRESHOLD
    assert result.candidates == []
    assert result.warnings, "degenerate calibration must warn explicitly"


def test_invalid_inputs_rejected() -> None:
    with pytest.raises(ValueError, match="same shape"):
        calibrate_threshold([0.5, 0.6], [True])
    with pytest.raises(ValueError, match="at least one"):
        calibrate_threshold([], [])
    with pytest.raises(ValueError, match="objective"):
        calibrate_threshold([0.5], [True], objective="accuracy")
    with pytest.raises(ValueError, match="grid"):
        calibrate_threshold([0.2, 0.8], [False, True], grid=[1.5])
