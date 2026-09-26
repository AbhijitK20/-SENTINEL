# SPDX-License-Identifier: Apache-2.0
"""Explainability engine for SENTINEL.

Attributions, counterfactuals, and deterministic natural-language explanations.
The method is chosen by what the model actually is - exact Shapley values for a
linear scorer, integrated gradients for the world model's risk head - and every
result names the method that produced it. See ``sentinel.explain.service`` for
the single place an explanation is produced.

Attention visualisation was removed from here along with the graph encoder it
depended on. Nothing in the pipeline produced an attention tensor: the temporal
model is a GRU, which has no attention weights to show, and the GAT that would
have supplied the graph ones was never wired into a trained model. The helpers
shaped arrays that no caller could obtain, so the two public functions were
unreachable. The ``temporal_attention`` and ``graph_attention`` fields remain on
``Explanation`` as ``None`` for contract compatibility; they are not populated
and should not be read as a claim that this system attends over anything.
"""

from __future__ import annotations

from sentinel.explain.contracts import Counterfactual, Explanation, FeatureAttribution
from sentinel.explain.counterfactual import minimal_counterfactual
from sentinel.explain.service import (
    counterfactual_for,
    explain_forecast,
    explain_state,
    explain_timeline,
)
from sentinel.explain.shap_engine import SHAPExplainer

__all__ = [
    "SHAPExplainer",
    "Counterfactual",
    "Explanation",
    "FeatureAttribution",
    "counterfactual_for",
    "explain_forecast",
    "explain_state",
    "explain_timeline",
    "minimal_counterfactual",
]
