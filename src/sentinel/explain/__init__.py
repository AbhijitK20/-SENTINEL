# SPDX-License-Identifier: Apache-2.0
"""Explainability engine for SENTINEL.

Provides SHAP-based attributions, attention visualization, counterfactuals,
and deterministic natural-language explanations.
"""

from __future__ import annotations

from sentinel.explain.attention import (
    get_graph_attention,
    get_temporal_attention,
    render_attention_heatmap,
)
from sentinel.explain.contracts import Counterfactual, Explanation, FeatureAttribution
from sentinel.explain.counterfactual import minimal_counterfactual
from sentinel.explain.service import explain_state, explain_timeline
from sentinel.explain.shap_engine import SHAPExplainer

__all__ = [
    "SHAPExplainer",
    "Counterfactual",
    "Explanation",
    "FeatureAttribution",
    "explain_state",
    "explain_timeline",
    "get_temporal_attention",
    "get_graph_attention",
    "minimal_counterfactual",
    "render_attention_heatmap",
]
