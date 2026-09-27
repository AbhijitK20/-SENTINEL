# SPDX-License-Identifier: Apache-2.0
"""Label efficiency: the curve must be readable, and the claim must be checkable.

The failure modes this guards, all of which produce a plausible-looking report:

- A flat curve reported without its ceiling, which is indistinguishable from a
  flat curve on a saturated task.
- An "indistinguishable" verdict computed against the *other* method's
  reference rather than the method's own.
- Nested budgets that are not actually nested, so the curve can rise by luck of
  which scenarios were drawn.
- A self-supervised step that quietly reads a label.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.label_efficiency import (
    PRETRAINED,
    SCRATCH,
    InsufficientLabels,
    LabelEfficiencyResult,
    encode,
    label_efficiency_curve,
    pretrain_encoder,
)


def _toy(n: int = 400, seed: int = 0) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Rows where a handful of columns carry the signal and the rest are noise."""
    rng = np.random.default_rng(seed)
    labels = (rng.random(n) < 0.4).astype(float)
    matrix = rng.normal(0.0, 1.0, size=(n, 12))
    matrix[:, 0] += labels * 3.0
    matrix[:, 1] -= labels * 2.0
    scenarios = np.array([f"s{i % 8:02d}" for i in range(n)])
    return matrix, labels, scenarios, np.arange(n)


def _curve(matrix: np.ndarray, labels: np.ndarray, scenarios: np.ndarray, budgets=(1, 2, 4, 8)):
    rows = np.arange(matrix.shape[0])
    return label_efficiency_curve(
        {SCRATCH: matrix, PRETRAINED: matrix[:, :4]},
        labels,
        rows,
        rows,
        scenarios,
        budgets,
        bootstrap_iterations=200,
        seed=0,
    )


# ── the self-supervised step ────────────────────────────────────────────


def test_pretraining_reports_using_no_labels() -> None:
    matrix, _labels, _scenarios, _rows = _toy()
    _model, result = pretrain_encoder(matrix, epochs=5, seed=0)
    assert result.labels_used == 0
    assert result.n_unlabelled_windows == matrix.shape[0]
    assert "no access to labels" in result.note


def test_pretraining_actually_learns_something() -> None:
    matrix, _labels, _scenarios, _rows = _toy()
    _model, result = pretrain_encoder(matrix, epochs=60, seed=0)
    assert len(result.reconstruction_loss) == 60
    assert result.final_loss < result.reconstruction_loss[0]


def test_pretraining_is_reproducible() -> None:
    matrix, _labels, _scenarios, _rows = _toy()
    _a, first = pretrain_encoder(matrix, epochs=8, seed=3)
    _b, second = pretrain_encoder(matrix, epochs=8, seed=3)
    assert first.reconstruction_loss == second.reconstruction_loss


def test_the_encoder_narrows_the_representation() -> None:
    matrix, _labels, _scenarios, _rows = _toy(n=100)
    model, result = pretrain_encoder(matrix, latent=3, hidden=8, epochs=3, seed=0)
    assert encode(model, matrix).shape == (100, 3)
    assert result.latent == 3


def test_pretraining_rejects_nonsense_input() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        pretrain_encoder(np.zeros((0, 4)))
    with pytest.raises(ValueError, match="mask_fraction"):
        pretrain_encoder(np.zeros((5, 4)), mask_fraction=1.5)
    with pytest.raises(ValueError, match="positive"):
        pretrain_encoder(np.zeros((5, 4)), latent=0)


# ── the curve ───────────────────────────────────────────────────────────


def test_the_curve_covers_every_method_and_budget() -> None:
    matrix, labels, scenarios, _rows = _toy()
    result = _curve(matrix, labels, scenarios)
    assert {(p.method, p.n_scenarios) for p in result.points} == {
        (m, b) for m in (SCRATCH, PRETRAINED) for b in (1, 2, 4, 8)
    }


def test_budgets_are_nested_prefixes() -> None:
    """Otherwise a curve can rise purely because a later draw got luckier."""
    matrix, labels, scenarios, _rows = _toy()
    result = _curve(matrix, labels, scenarios)
    scratch = sorted((p for p in result.points if p.method == SCRATCH), key=lambda p: p.n_scenarios)
    for smaller, larger in zip(scratch, scratch[1:], strict=False):
        assert smaller.n_scenarios < larger.n_scenarios
        assert smaller.n_samples < larger.n_samples


def test_each_point_is_compared_against_its_own_ceiling() -> None:
    """The verdict must not borrow the other method's reference."""
    matrix, labels, scenarios, _rows = _toy()
    result = _curve(matrix, labels, scenarios)
    for point in result.points:
        assert point.reference_brier == pytest.approx(result.references[point.method])
        assert point.loss_from_full == pytest.approx(point.brier - point.reference_brier)


def test_headroom_is_positive_when_labels_are_worth_having() -> None:
    matrix, labels, scenarios, _rows = _toy()
    result = _curve(matrix, labels, scenarios)
    # More labels must not make the toy problem worse, so the one-scenario model
    # sits above the full-data ceiling.
    for method, headroom in result.headroom.items():
        assert headroom > 0.0, f"{method} got worse with more labels: {headroom}"


def test_a_saturated_task_is_reported_as_saturated() -> None:
    """The honest null: when one scenario already suffices, say so."""
    matrix, labels, scenarios, _rows = _toy()
    perfect = labels.reshape(-1, 1).repeat(matrix.shape[1], axis=1) + matrix * 0.0
    result = label_efficiency_curve(
        {SCRATCH: perfect, PRETRAINED: perfect[:, :3]},
        labels,
        np.arange(labels.size),
        np.arange(labels.size),
        scenarios,
        (1, 2, 4),
        bootstrap_iterations=200,
        seed=0,
    )
    assert "saturated at one labelled scenario" in result.note


def test_the_note_names_the_learned_representation_as_the_subject() -> None:
    """Regression: the verdict once named the *better* method as the winner.

    The sentence has to be about the representation - the thing under test - and
    its polarity has to follow the numbers, not the ranking of two arbitrary
    labels.
    """
    matrix, labels, scenarios, _rows = _toy()
    result = _curve(matrix, labels, scenarios)
    expected = "beats" if result.references[PRETRAINED] < result.references[SCRATCH] else "loses"
    assert f"the learned representation {expected}" in result.note
    for reference in result.references.values():
        assert f"{reference:.4f}" in result.note


def test_the_interval_brackets_the_reported_loss() -> None:
    matrix, labels, scenarios, _rows = _toy()
    for point in _curve(matrix, labels, scenarios).points:
        assert point.ci_low <= point.loss_from_full <= point.ci_high


def test_a_budget_larger_than_the_training_split_is_refused() -> None:
    matrix, labels, scenarios, rows = _toy(n=80)
    with pytest.raises(InsufficientLabels, match="exceeds"):
        label_efficiency_curve(
            {SCRATCH: matrix, PRETRAINED: matrix[:, :4]},
            labels,
            rows,
            rows,
            scenarios,
            (1, 999),
            bootstrap_iterations=100,
        )


def test_a_single_class_budget_is_refused_rather_than_fitted() -> None:
    matrix, labels, _scenarios, rows = _toy(n=80)
    # Scenarios that split by class, so a one-scenario budget holds one class
    # only. Fitting anything to that would be a coin flip wearing a score.
    by_class = np.where(labels > 0.5, "pos", "neg")
    with pytest.raises(InsufficientLabels, match="only one class"):
        label_efficiency_curve(
            {SCRATCH: matrix, PRETRAINED: matrix[:, :4]},
            labels,
            rows,
            rows,
            by_class,
            (1,),
            bootstrap_iterations=100,
        )


def test_nonsense_arguments_are_rejected() -> None:
    matrix, labels, scenarios, rows = _toy(n=80)
    with pytest.raises(ValueError, match="at least one label budget"):
        label_efficiency_curve(
            {SCRATCH: matrix}, labels, rows, rows, scenarios, (), bootstrap_iterations=50
        )
    with pytest.raises(ValueError, match="start at one"):
        label_efficiency_curve(
            {SCRATCH: matrix}, labels, rows, rows, scenarios, (0,), bootstrap_iterations=50
        )
    with pytest.raises(ValueError, match="unknown methods"):
        label_efficiency_curve(
            {"magic": matrix}, labels, rows, rows, scenarios, (1,), bootstrap_iterations=50
        )


# ── reporting ───────────────────────────────────────────────────────────


def test_the_result_serialises_with_its_ceiling_and_pretraining() -> None:
    matrix, labels, scenarios, _rows = _toy()
    model, pretraining = pretrain_encoder(matrix, epochs=3, seed=0)
    result = _curve(matrix, labels, scenarios, budgets=(1, 2))
    result.pretraining = pretraining
    payload = result.as_dict()
    assert set(payload["references"]) == {SCRATCH, PRETRAINED}
    assert payload["pretraining"]["labels_used"] == 0
    assert len(payload["curve"]) == 4
    assert payload["version"]


def test_for_budget_indexes_by_method() -> None:
    matrix, labels, scenarios, _rows = _toy()
    result = _curve(matrix, labels, scenarios)
    at_two = result.for_budget(2)
    assert set(at_two) == {SCRATCH, PRETRAINED}
    assert all(p.n_scenarios == 2 for p in at_two.values())


def test_an_empty_result_still_renders_a_note() -> None:
    assert LabelEfficiencyResult().as_dict()["curve"] == []


def test_encode_returns_finite_plain_floats() -> None:
    matrix, _labels, _scenarios, _rows = _toy(n=50)
    model, _result = pretrain_encoder(matrix, latent=4, hidden=8, epochs=2, seed=0)
    encoded = encode(model, matrix)
    assert encoded.shape == (50, 4)
    assert encoded.dtype == np.float64
    assert np.isfinite(encoded).all()
