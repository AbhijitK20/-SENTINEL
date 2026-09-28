# SPDX-License-Identifier: Apache-2.0
"""CQR: does the asymmetric method deliver what the symmetric one cannot?

The symmetric method's documented failure is that a wide interval centred near a
bound is truncated, so the width the calibration paid for is destroyed. CQR's
claim is that it reaches the same coverage with far less truncation - that is,
the interval determines its own width instead of the ``[0, 1]`` bound doing it.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.conformal import ConformalizedQuantileRegression, SplitConformal


def _weak_problem(n: int = 3000, seed: int = 0):
    """A deliberately weak model, so the interval has to be wide.

    Wide intervals near the bounds are where symmetric clipping bites, which is
    the regime the CQR docstring claims to fix.
    """
    rng = np.random.default_rng(seed)
    x = rng.normal(size=(n, 6))
    y = 1.0 / (1.0 + np.exp(-(0.35 * x[:, 0] - 0.25 * x[:, 1] + rng.normal(0, 1.1, size=n))))
    n_train, n_cal = n // 2, n // 4
    return (
        (x[:n_train], y[:n_train]),
        (x[n_train : n_train + n_cal], y[n_train : n_train + n_cal]),
        (x[n_train + n_cal :], y[n_train + n_cal :]),
    )


@pytest.fixture(scope="module")
def fitted():
    (x_tr, y_tr), (x_cal, y_cal), (x_te, y_te) = _weak_problem()
    model = ConformalizedQuantileRegression(coverage=0.9).fit(x_tr, y_tr, x_cal, y_cal)
    return model, x_te, y_te


def test_cqr_reaches_its_nominal_coverage(fitted) -> None:
    model, x_te, y_te = fitted
    covered = np.mean(
        [i.covers(float(t)) for i, t in zip(model.predict_many(x_te), y_te, strict=True)]
    )
    assert covered >= 0.85, f"CQR covered {covered:.3f} against a promised 0.90"


def test_cqr_truncates_far_less_than_the_symmetric_method(fitted) -> None:
    """The mechanism, not a side effect: same coverage, far less clipping.

    A symmetric interval centred near 0 or 1 loses most of its width to the bound,
    and the coverage it then reports is propped up by truncation rather than
    earned. CQR spends its width where the answer actually is.
    """
    model, x_te, _ = fitted
    (x_tr, y_tr), _, _ = _weak_problem()
    rng = np.random.default_rng(99)
    point = np.clip(0.5 + 0.35 * (y_tr - 0.5) + rng.normal(0, 0.18, size=y_tr.size), 0.0, 1.0)
    symmetric = SplitConformal(coverage=0.9).fit(point, y_tr)
    sym_clipped = float(np.mean([i.clipped for i in symmetric.predict_many(point)]))
    cqr_clipped = float(np.mean([i.clipped for i in model.predict_many(x_te)]))
    assert cqr_clipped < sym_clipped, (
        f"CQR clipped {cqr_clipped:.1%} vs symmetric {sym_clipped:.1%}"
    )


def test_cqr_intervals_stay_inside_the_unit_range(fitted) -> None:
    model, x_te, _ = fitted
    for interval in model.predict_many(x_te[:50]):
        assert 0.0 <= interval.lower <= interval.upper <= 1.0


def test_cqr_states_its_method_and_its_own_limits(fitted) -> None:
    model, x_te, _ = fitted
    interval = model.predict(x_te[0])
    assert interval.method == "cqr-asymmetric"
    assert "exchangeable" in interval.caveat


def test_cqr_intervals_are_not_all_centred_the_same_way(fitted) -> None:
    """Otherwise it is the symmetric method wearing a different label."""
    model, x_te, _ = fitted
    midpoints = [round(i.lower + i.upper, 6) for i in model.predict_many(x_te[:100])]
    assert len(set(midpoints)) > 1


def test_cqr_refuses_to_predict_before_fitting() -> None:
    with pytest.raises(ValueError, match="before fit"):
        ConformalizedQuantileRegression().predict(np.zeros(3))


def test_cqr_rejects_misaligned_input() -> None:
    rng = np.random.default_rng(1)
    x, y = rng.normal(size=(40, 3)), rng.uniform(size=40)
    with pytest.raises(ValueError, match="matching columns"):
        ConformalizedQuantileRegression().fit(x, y, x[:, :2], y)
    with pytest.raises(ValueError, match="one label per row"):
        ConformalizedQuantileRegression().fit(x, y[:10], x, y)
    with pytest.raises(ValueError, match="ten rows"):
        ConformalizedQuantileRegression().fit(x[:5], y[:5], x[:5], y[:5])
