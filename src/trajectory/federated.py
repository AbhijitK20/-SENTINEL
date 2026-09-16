# SPDX-License-Identifier: Apache-2.0
"""Federated learning simulation (roadmap Phase 11): FedAvg over clients.

Simulates cross-silo federated averaging for the logistic-regression
baseline: each client trains on its own scenarios and only model weights
plus sample counts are shared — no raw data ever leaves a client. This is a
single-process simulation of the protocol (no network, no secure
aggregation); production federated learning needs those and stays in
ROADMAP.md.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from trajectory.config import BaselineConfig
from trajectory.targets import LabelledState, SequenceSample, SplitManifest


@dataclass(frozen=True)
class ClientUpdate:
    """One client's contribution: weights plus the count that weights them."""

    client_id: str
    coef: np.ndarray
    intercept: float
    n_samples: int


@dataclass(frozen=True)
class FederatedResult:
    """FedAvg output, shaped like a trained baseline's model payload."""

    coef: np.ndarray
    intercept: float
    n_clients: int
    total_samples: int
    round: int


def train_client(
    client_id: str,
    labelled_states: list[LabelledState],
    samples: list[SequenceSample],
    manifest: SplitManifest,
    *,
    config: BaselineConfig | None = None,
    seed: int = 7,
) -> ClientUpdate:
    """Train the baseline on one client's local data and return weights only."""
    from trajectory.baseline import train_baseline

    run = train_baseline(
        labelled_states,
        samples,
        manifest,
        config=config or BaselineConfig(),
        seed=seed,
    )
    model = run.model
    return ClientUpdate(
        client_id=client_id,
        coef=np.asarray(model.coef_[0], dtype=float),
        intercept=float(model.intercept_[0]),
        n_samples=len(samples),
    )


def fed_average(updates: list[ClientUpdate], *, round_number: int = 1) -> FederatedResult:
    """Sample-weighted average of client weights (FedAvg, one round).

    The average is exact: sum(w_i * n_i) / sum(n_i) per coefficient, matching
    the centralized objective when client datasets are IID. Non-IID drift
    across clients is expected and is what multi-round training would address.
    """
    if not updates:
        raise ValueError("fed_average needs at least one client update")
    total = sum(update.n_samples for update in updates)
    if total <= 0:
        raise ValueError("client updates carry no samples")
    dim = updates[0].coef.shape[0]
    for update in updates:
        if update.coef.shape[0] != dim:
            raise ValueError("client weight dimensions disagree — feature schemas differ")
    coef = sum((update.coef * update.n_samples for update in updates), start=np.zeros(dim)) / total
    intercept = sum(update.intercept * update.n_samples for update in updates) / total
    return FederatedResult(
        coef=coef,
        intercept=float(intercept),
        n_clients=len(updates),
        total_samples=total,
        round=round_number,
    )


__all__ = ["ClientUpdate", "FederatedResult", "fed_average", "train_client"]
