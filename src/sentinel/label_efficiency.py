# SPDX-License-Identifier: Apache-2.0
"""How many labelled scenarios does this need, and does unlabelled data help?

Two questions, one experiment:

1. **Label efficiency.** How much does performance move between one labelled
   scenario and all of them? A curve is only interpretable next to its own
   ceiling, so every point is reported against a full-data reference trained the
   same way. A flat curve and a saturated curve look identical without it.
2. **Self-supervised pretraining.** A masked-feature autoencoder is fitted on
   train-split windows *without ever reading a label*, and the same label budgets
   are then spent on its representation.

The pretraining is a fair fight only if the comparison is stated carefully, so it
is: ``scratch`` sees all 98 raw features, ``pretrained`` sees the encoder's
narrower output. That dimension difference is part of what a representation *is*,
not a confound to hide, and every row reports its own width.

Deliberately not attempted: any claim that this transfers to CIC-IDS2017 or to
any real network. It is measured on the synthetic generator, where the
infiltration task is close to separable, and a saturated task cannot show a
label-efficiency effect even when one exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import torch
import torch.nn as nn

from sentinel.telemetry_budget import bootstrap_difference

LABEL_EFFICIENCY_VERSION = "label-efficiency-v1"

SCRATCH = "scratch"
PRETRAINED = "pretrained"
METHODS = (SCRATCH, PRETRAINED)

# The unlabelled pool. Bigger than any label budget, which is the point: the
# encoder sees windows whose labels are never touched.
DEFAULT_LATENT = 16
DEFAULT_HIDDEN = 64
DEFAULT_EPOCHS = 200
DEFAULT_MASK_FRACTION = 0.3


class InsufficientLabels(ValueError):
    """Raised when a label budget cannot support the comparison it is asked for."""


@dataclass
class PretrainingResult:
    """What the self-supervised step actually achieved, before any labels."""

    latent: int
    hidden: int
    epochs: int
    mask_fraction: float
    n_unlabelled_windows: int
    reconstruction_loss: list[float] = field(default_factory=list)
    labels_used: int = 0
    note: str = ""

    @property
    def final_loss(self) -> float | None:
        return self.reconstruction_loss[-1] if self.reconstruction_loss else None

    def as_dict(self) -> dict:
        return {
            "version": LABEL_EFFICIENCY_VERSION,
            "latent": self.latent,
            "hidden": self.hidden,
            "epochs": self.epochs,
            "mask_fraction": self.mask_fraction,
            "n_unlabelled_windows": self.n_unlabelled_windows,
            "reconstruction_loss": [round(v, 6) for v in self.reconstruction_loss],
            "labels_used": self.labels_used,
            "note": self.note,
        }


class MaskedFeatureEncoder(nn.Module):
    """Encoder/decoder pair trained to rebuild masked features from the rest.

    Masking rather than predicting the next window: the feature vector is a
    summary of a window that is already fixed, so there is no ordering to exploit
    and a denoising objective is the honest self-supervised task available here.
    """

    def __init__(self, n_features: int, latent: int, hidden: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(n_features, hidden),
            nn.ReLU(),
            nn.Linear(hidden, latent),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden),
            nn.ReLU(),
            nn.Linear(hidden, n_features),
        )

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        encoded = self.encoder(x)
        return encoded, self.decoder(encoded)


def pretrain_encoder(
    unlabelled: np.ndarray,
    *,
    latent: int = DEFAULT_LATENT,
    hidden: int = DEFAULT_HIDDEN,
    epochs: int = DEFAULT_EPOCHS,
    mask_fraction: float = DEFAULT_MASK_FRACTION,
    seed: int = 0,
) -> tuple[MaskedFeatureEncoder, PretrainingResult]:
    """Fit a masked-feature autoencoder on windows whose labels are never read.

    ``labels_used`` is a field on the result rather than a comment because the
    whole claim is that this step is unsupervised; a reader should not have to
    take it on trust.
    """
    matrix = np.asarray(unlabelled, dtype=np.float32)
    if matrix.ndim != 2 or matrix.shape[0] == 0:
        raise ValueError("unlabelled must be a non-empty (n, n_features) matrix")
    if not 0.0 < mask_fraction < 1.0:
        raise ValueError("mask_fraction must be between zero and one")
    if latent < 1 or hidden < 1:
        raise ValueError("latent and hidden must be positive")

    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)
    generator = torch.Generator().manual_seed(seed)

    model = MaskedFeatureEncoder(matrix.shape[1], latent, hidden)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-2)
    data = torch.from_numpy(matrix)
    losses: list[float] = []
    for _epoch in range(epochs):
        permutation = torch.randperm(data.shape[0], generator=generator)
        keep = max(1, int(round(data.shape[1] * (1.0 - mask_fraction))))
        covered = 0.0
        for start in range(0, data.shape[0], 64):
            batch = data[permutation[start : start + 64]]
            mask = torch.zeros_like(batch)
            # Mask whole feature columns within a batch, so the encoder cannot
            # learn to read the answer off a neighbouring row.
            for column in torch.randperm(batch.shape[1], generator=generator)[:keep]:
                mask[:, column] = 1.0
            _, reconstructed = model(batch * mask)
            loss = nn.functional.mse_loss(reconstructed, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            covered += float(loss.detach()) * batch.shape[0]
        losses.append(covered / data.shape[0])

    return model, PretrainingResult(
        latent=latent,
        hidden=hidden,
        epochs=epochs,
        mask_fraction=mask_fraction,
        n_unlabelled_windows=int(matrix.shape[0]),
        reconstruction_loss=losses,
        labels_used=0,
        note=(
            "Fitted on train-split windows with no access to labels. A falling "
            "reconstruction loss means the features are mutually predictable, "
            "which is a property of the generator and not evidence of a useful "
            "representation."
        ),
    )


@torch.no_grad()
def encode(model: MaskedFeatureEncoder, matrix: np.ndarray) -> np.ndarray:
    """Encode unmasked rows, which is how the downstream classifier sees them."""
    data = torch.from_numpy(np.asarray(matrix, dtype=np.float32))
    return model.encoder(data).numpy().astype(float)


@dataclass
class BudgetPoint:
    """One cell of the curve: a method at one label budget."""

    method: str
    n_scenarios: int
    n_samples: int
    n_features: int
    brier: float
    reference_brier: float
    loss_from_full: float
    ci_low: float
    ci_high: float
    indistinguishable: bool

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "n_scenarios": self.n_scenarios,
            "n_samples": self.n_samples,
            "n_features": self.n_features,
            "brier": round(self.brier, 6),
            "reference_brier": round(self.reference_brier, 6),
            "loss_from_full": round(self.loss_from_full, 6),
            "ci_low": round(self.ci_low, 6),
            "ci_high": round(self.ci_high, 6),
            "indistinguishable_from_full": self.indistinguishable,
        }


@dataclass
class LabelEfficiencyResult:
    """The curve, its ceiling, and what it does and does not show."""

    points: list[BudgetPoint] = field(default_factory=list)
    references: dict[str, float] = field(default_factory=dict)
    first_budget_brier: dict[str, float] = field(default_factory=dict)
    headroom: dict[str, float] = field(default_factory=dict)
    pretraining: PretrainingResult | None = None
    note: str = ""

    def for_budget(self, n_scenarios: int) -> dict[str, BudgetPoint]:
        return {p.method: p for p in self.points if p.n_scenarios == n_scenarios}

    def as_dict(self) -> dict:
        return {
            "version": LABEL_EFFICIENCY_VERSION,
            "references": {k: round(v, 6) for k, v in self.references.items()},
            "first_budget_brier": {k: round(v, 6) for k, v in self.first_budget_brier.items()},
            "headroom": {k: round(v, 6) for k, v in self.headroom.items()},
            "pretraining": self.pretraining.as_dict() if self.pretraining else None,
            "curve": [p.as_dict() for p in self.points],
            "note": self.note,
        }


def label_efficiency_curve(
    representations: dict[str, np.ndarray],
    labels: np.ndarray,
    train_rows: np.ndarray,
    evaluation_rows: np.ndarray,
    scenario_of_row: np.ndarray,
    budgets: tuple[int, ...],
    *,
    bootstrap_iterations: int = 2000,
    seed: int = 0,
) -> LabelEfficiencyResult:
    """Fit each method at each label budget and score it on held-out windows.

    ``representations`` maps a method name to its feature matrix over all rows.
    Budgets are nested prefixes of one seeded shuffle of the *training*
    scenarios, so a point at 4 scenarios is a strict subset of the point at 8 and
    the curve cannot improve by luck of which scenarios were drawn.

    Evaluation happens on ``evaluation_rows`` only, and the bootstrap is paired
    against the same method trained on every scenario, so "indistinguishable"
    means this budget cannot be distinguished from that method's own ceiling.
    """
    from sklearn.linear_model import LogisticRegression

    if not budgets:
        raise ValueError("at least one label budget is required")
    if any(b < 1 for b in budgets):
        raise ValueError("label budgets are counted in scenarios and start at one")
    unknown = set(representations) - set(METHODS)
    if unknown:
        raise ValueError(f"unknown methods: {sorted(unknown)}")
    y = np.asarray(labels, dtype=float)
    scenario_of_row = np.asarray(scenario_of_row)
    train_scenarios = np.unique(scenario_of_row[train_rows])
    if max(budgets) > train_scenarios.size:
        raise InsufficientLabels(
            f"budget of {max(budgets)} scenarios exceeds the {train_scenarios.size} "
            "available in the training split"
        )

    rng = np.random.default_rng(seed)
    order = list(train_scenarios)
    rng.shuffle(order)

    # Per-window squared error is additive over windows, which is what makes the
    # paired bootstrap meaningful; F1 is not, and a bootstrap over it would be
    # measuring the resampling.
    def per_window(method: str, chosen: list[str]) -> np.ndarray:
        matrix = np.asarray(representations[method], dtype=float)
        rows = train_rows[np.isin(scenario_of_row[train_rows], chosen)]
        if np.unique(y[rows]).size < 2:
            raise InsufficientLabels(
                f"{len(chosen)} scenario(s) of {method} training data contain only "
                "one class, so no model can be fitted"
            )
        model = LogisticRegression(max_iter=2000, random_state=seed)
        model.fit(matrix[rows], y[rows])
        predicted = model.predict_proba(matrix[evaluation_rows])[:, 1]
        return (predicted - y[evaluation_rows]) ** 2

    result = LabelEfficiencyResult()
    for method in METHODS:
        result.references[method] = float(per_window(method, list(order)).mean())

    for method in METHODS:
        first: float | None = None
        for budget in budgets:
            vector = per_window(method, order[:budget])
            score = float(vector.mean())
            if first is None:
                first = score
            reference = result.references[method]
            low, high = bootstrap_difference(
                vector,
                np.full(vector.shape, reference),
                iterations=bootstrap_iterations,
                seed=seed,
            )
            result.points.append(
                BudgetPoint(
                    method=method,
                    n_scenarios=budget,
                    n_samples=int(np.isin(scenario_of_row[train_rows], order[:budget]).sum()),
                    n_features=int(np.asarray(representations[method]).shape[1]),
                    brier=score,
                    reference_brier=reference,
                    loss_from_full=score - reference,
                    ci_low=low,
                    ci_high=high,
                    indistinguishable=low <= 0.0 <= high,
                )
            )
        result.headroom[method] = (first or 0.0) - result.references[method]
        result.first_budget_brier[method] = first or 0.0

    result.note = _note(result)
    return result


def _note(result: LabelEfficiencyResult) -> str:
    """State the finding, including the case where there is nothing to find."""
    saturated = [m for m, h in result.headroom.items() if abs(h) < 0.01]
    parts = [
        "Headroom is the Brier gap between training on one scenario and on all of "
        "them, positive when there is room left to improve: "
        + ", ".join(f"{m} {h:+.4f}" for m, h in sorted(result.headroom.items()))
        + "."
    ]
    if len(saturated) == len(METHODS):
        parts.append(
            "Both methods are saturated at one labelled scenario, so this task "
            "cannot demonstrate a label-efficiency effect and cannot show that "
            "pretraining helps. The curve is flat because there is no headroom to "
            "recover, not because the labels were plentiful."
        )
    else:
        if PRETRAINED not in result.references or SCRATCH not in result.references:
            parts.append("Only one method was fitted, so there is nothing to compare.")
        else:
            learned = result.references[PRETRAINED]
            raw_features = result.references[SCRATCH]
            if learned < raw_features:
                verdict = (
                    f"the learned representation beats the raw features ({learned:.4f} "
                    f"against {raw_features:.4f})"
                )
            else:
                verdict = (
                    f"the learned representation loses to the raw features it replaced "
                    f"({learned:.4f} against {raw_features:.4f}), so reconstructing the "
                    f"features discarded signal the classifier needed"
                )
            parts.append(f"Ceiling comparison: {verdict}.")
    parts.append(
        "Measured on the synthetic generator. This is a statement about the "
        "generator, not about how many labels a real campaign needs."
    )
    return " ".join(parts)


__all__ = [
    "LABEL_EFFICIENCY_VERSION",
    "METHODS",
    "PRETRAINED",
    "SCRATCH",
    "BudgetPoint",
    "InsufficientLabels",
    "LabelEfficiencyResult",
    "MaskedFeatureEncoder",
    "PretrainingResult",
    "encode",
    "label_efficiency_curve",
    "pretrain_encoder",
]
