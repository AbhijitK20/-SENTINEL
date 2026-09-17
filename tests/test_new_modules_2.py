# SPDX-License-Identifier: Apache-2.0
"""Tests for streaming, graph, world_model, and explain modules."""

from __future__ import annotations

import numpy as np

from sentinel.explain.contracts import (
    Counterfactual,
    Explanation,
    FeatureAttribution,
)
from sentinel.graph.state import NetworkGraph
from sentinel.streaming.windowing import EventTimeWindower

# ── Streaming / Windowing ───────────────────────────────────────────────


class TestWindowing:
    def test_windower_creates_windows(self) -> None:
        w = EventTimeWindower(window_size=60, window_stride=30)
        assert w.window_size == 60
        assert w.window_stride == 30


# ── Graph / State ───────────────────────────────────────────────────────


class TestGraphState:
    def test_empty_window_produces_empty_graph(self) -> None:
        graph = NetworkGraph(
            node_ids=[],
            node_features=np.empty((0, 0)),
            edge_index=np.empty((2, 0), dtype=int),
            edge_features=np.empty((0, 0)),
            node_feature_names=[],
            edge_feature_names=[],
        )
        assert len(graph.node_ids) == 0
        assert graph.edge_index.shape[1] == 0


# ── Explain / Contracts ─────────────────────────────────────────────────


class TestExplainContracts:
    def test_explanation_creation(self) -> None:
        explanation = Explanation(
            prediction=0.87,
            risk_score=0.87,
            stage_probs={"Unknown": 1.0},
            feature_attributions=[
                FeatureAttribution(
                    name="dst_port_nunique",
                    value=47.0,
                    shap_value=0.312,
                    method="exact",
                )
            ],
            method="exact",
        )
        assert explanation.risk_score == 0.87
        assert len(explanation.feature_attributions) == 1

    def test_counterfactual_creation(self) -> None:
        cf = Counterfactual(
            original=0.87,
            target=0.14,
            features=[
                FeatureAttribution(
                    name="a",
                    value=0.5,
                    shap_value=-0.73,
                    method="exact",
                )
            ],
            predicted_impact=-0.73,
        )
        assert cf.original == 0.87
        assert cf.target == 0.14
