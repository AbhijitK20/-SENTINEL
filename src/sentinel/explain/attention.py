# SPDX-License-Identifier: Apache-2.0
"""Attention visualization for temporal and graph attention."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class AttentionResult:
    """Result of attention computation."""

    weights: np.ndarray
    heads: int
    layers: int
    seq_len: int
    attention_type: str


def get_temporal_attention(
    attention_weights: np.ndarray,
    layer: int = -1,
    head: int = 0,
) -> AttentionResult:
    """Extract temporal attention from a sequence model.

    Args:
        attention_weights: (layers, heads, seq_len, seq_len) attention tensor.
        layer: Layer to extract (-1 for last).
        head: Head to extract.

    Returns:
        AttentionResult with attention weights.
    """
    if attention_weights.ndim == 4:
        weights = attention_weights[layer, head]
    elif attention_weights.ndim == 3:
        weights = attention_weights[head]
    else:
        weights = attention_weights

    seq_len = weights.shape[0]

    return AttentionResult(
        weights=weights,
        heads=attention_weights.shape[1] if attention_weights.ndim >= 3 else 1,
        layers=attention_weights.shape[0] if attention_weights.ndim >= 4 else 1,
        seq_len=seq_len,
        attention_type="temporal",
    )


def get_graph_attention(
    alpha: np.ndarray,
    edge_index: np.ndarray,
    node_names: list[str],
) -> AttentionResult:
    """Extract graph attention from GAT.

    Args:
        alpha: (num_edges, num_heads) attention weights.
        edge_index: (2, num_edges) edge indices.
        node_names: List of node names.

    Returns:
        AttentionResult with attention weights.
    """
    num_nodes = len(node_names)
    num_heads = alpha.shape[1] if alpha.ndim > 1 else 1

    # Aggregate attention per node
    node_attention = np.zeros(num_nodes)
    for edge_idx in range(edge_index.shape[1]):
        dst = edge_index[1, edge_idx]
        node_attention[dst] += alpha[edge_idx].mean()

    return AttentionResult(
        weights=node_attention,
        heads=num_heads,
        layers=1,
        seq_len=num_nodes,
        attention_type="graph",
    )


def render_attention_heatmap(
    attention: AttentionResult,
    labels: list[str] | None = None,
    title: str = "Attention Weights",
) -> str:
    """Render attention as a simple text heatmap.

    Returns:
        String representation of attention heatmap.
    """
    weights = attention.weights
    if weights.ndim == 1:
        # Node-level attention
        lines = [f"=== {title} ==="]
        max_val = weights.max() if weights.max() > 0 else 1.0
        for i, val in enumerate(weights):
            bar_len = int(40 * val / max_val) if max_val > 0 else 0
            label = labels[i] if labels else f"Node {i}"
            lines.append(f"{label:20s} {'█' * bar_len} {val:.3f}")
        return "\n".join(lines)
    else:
        # Matrix attention
        lines = [f"=== {title} ({weights.shape[0]}×{weights.shape[1]}) ==="]
        for i in range(weights.shape[0]):
            row = " ".join(f"{v:.2f}" for v in weights[i])
            lines.append(f"Row {i}: {row}")
        return "\n".join(lines)


def compute_attention_entropy(attention: AttentionResult) -> float:
    """Compute entropy of attention distribution.

    Higher entropy = more uniform attention.
    Lower entropy = more focused attention.
    """
    weights = attention.weights.flatten()
    weights = weights / weights.sum() if weights.sum() > 0 else weights
    weights = weights[weights > 0]
    return float(-np.sum(weights * np.log(weights + 1e-10)))
