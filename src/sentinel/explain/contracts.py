# SPDX-License-Identifier: Apache-2.0
"""Contracts for explanation outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import numpy as np


@dataclass
class FeatureAttribution:
    """Single feature attribution."""

    name: str
    value: float
    shap_value: float
    method: Literal["exact", "kernel", "linear", "gradient", "attention"]
    baseline_value: float = 0.0

    @property
    def impact(self) -> float:
        return self.shap_value

    @property
    def direction(self) -> str:
        return "increases" if self.shap_value > 0 else "decreases"


@dataclass
class Explanation:
    """Complete explanation for a single prediction."""

    prediction: float
    risk_score: float
    stage_probs: dict[str, float]
    feature_attributions: list[FeatureAttribution]
    temporal_attention: np.ndarray | None = None
    graph_attention: np.ndarray | None = None
    counterfactual: Counterfactual | None = None
    faithfulness_score: float = 0.0
    stability_score: float = 0.0
    method: str = "exact"

    def top_k(self, k: int = 5) -> list[FeatureAttribution]:
        return sorted(self.feature_attributions, key=lambda x: abs(x.shap_value), reverse=True)[:k]

    def natural_language(self) -> str:
        """Generate deterministic NL explanation from attributions."""
        parts = [
            f"Infiltration probability {self.risk_score:.2f}",
        ]

        # Stage
        if self.stage_probs:
            top_stage = max(self.stage_probs, key=self.stage_probs.get)  # type: ignore
            parts.append(f"Stage: {top_stage}")

        # Top features
        top = self.top_k(3)
        if top:
            parts.append("Driven by:")
            for fa in top:
                parts.append(
                    f"  {fa.name} ({fa.value:.3f}, {fa.direction} {abs(fa.shap_value):.3f})"
                )

        # Counterfactual
        if self.counterfactual:
            parts.append(self.counterfactual.natural_language())

        return ". ".join(parts) + "."


@dataclass
class Counterfactual:
    """Minimal feature change to reach target probability."""

    original: float
    target: float
    features: list[FeatureAttribution]
    predicted_impact: float

    def natural_language(self) -> str:
        """Generate deterministic NL explanation of counterfactual."""
        if not self.features:
            return "No feasible counterfactual found"

        changes = []
        for fa in self.features[:3]:
            changes.append(f"{fa.name} from {fa.value:.2f} to {fa.baseline_value:.2f}")

        drop_from = self.original
        drop_to = self.predicted_impact
        joined = " and ".join(changes)
        return f"If {joined}, probability would drop from {drop_from:.2f} to {drop_to:.2f}"
