# SPDX-License-Identifier: Apache-2.0
"""Graph Attention Network (GAT) encoder — hand-rolled in plain PyTorch.

No PyTorch Geometric dependency. Uses index_add_ + segment softmax.
2 layers, 4 heads, hidden 64, ELU. Readout: concat(mean, max, attention-weighted sum).
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

from sentinel.graph.state import NetworkGraph


class MultiHeadGATLayer(nn.Module):
    """Single multi-head graph attention layer."""

    def __init__(self, in_dim: int, out_dim: int, num_heads: int = 4) -> None:
        super().__init__()
        self.num_heads = num_heads
        self.head_dim = out_dim // num_heads
        assert out_dim % num_heads == 0, "out_dim must be divisible by num_heads"

        self.W = nn.Linear(in_dim, out_dim, bias=False)
        self.a_src = nn.Parameter(torch.randn(num_heads, self.head_dim))
        self.a_dst = nn.Parameter(torch.randn(num_heads, self.head_dim))
        self.leaky_relu = nn.LeakyReLU(0.2)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Forward pass.

        Args:
            x: (num_nodes, in_dim) node features.
            edge_index: (2, num_edges) edge indices.

        Returns:
            out: (num_nodes, out_dim) updated node features.
            alpha: (num_edges, num_heads) attention weights.
        """
        num_nodes = x.size(0)
        H, D = self.num_heads, self.head_dim

        # Linear transform
        Wh = self.W(x)  # (num_nodes, out_dim)
        Wh = Wh.view(num_nodes, H, D)  # (num_nodes, H, D)

        src, dst = edge_index[0], edge_index[1]

        # Compute attention scores
        e_src = (Wh[src] * self.a_src).sum(dim=-1)  # (num_edges, H)
        e_dst = (Wh[dst] * self.a_dst).sum(dim=-1)  # (num_edges, H)
        e = self.leaky_relu(e_src + e_dst)  # (num_edges, H)

        # Segment softmax: normalize over incoming edges per node
        alpha = self._segment_softmax(e, dst, num_nodes)  # (num_edges, H)

        # Aggregate messages
        msg = Wh[src] * alpha.unsqueeze(-1)  # (num_edges, H, D)
        out = torch.zeros(num_nodes, H, D, device=x.device)
        out.scatter_add_(0, dst.unsqueeze(-1).unsqueeze(-1).expand_as(msg), msg)
        out = out.view(num_nodes, H * D)

        return out, alpha

    def _segment_softmax(
        self, e: torch.Tensor, segment_ids: torch.Tensor, num_segments: int
    ) -> torch.Tensor:
        """Softmax over segments (incoming edges per node)."""
        # Subtract max per segment for numerical stability
        max_vals = torch.zeros(num_segments, e.size(1), device=e.device)
        max_vals.scatter_reduce_(0, segment_ids.unsqueeze(1).expand_as(e), e, reduce="amax")
        e = e - max_vals[segment_ids]

        exp_e = torch.exp(e)
        sum_exp = torch.zeros(num_segments, e.size(1), device=e.device)
        sum_exp.scatter_add_(0, segment_ids.unsqueeze(1).expand_as(exp_e), exp_e)
        return exp_e / (sum_exp[segment_ids] + 1e-8)


class GATEncoder(nn.Module):
    """Multi-layer GAT encoder with readout.

    Architecture:
        - 2 GAT layers with 4 heads each
        - ELU activation
        - Readout: concat(mean, max, attention-weighted sum)
    """

    def __init__(
        self,
        in_dim: int,
        hidden_dim: int = 64,
        num_heads: int = 4,
        num_layers: int = 2,
    ) -> None:
        super().__init__()
        self.layers = nn.ModuleList()
        self.layers.append(MultiHeadGATLayer(in_dim, hidden_dim, num_heads))
        for _ in range(num_layers - 1):
            self.layers.append(MultiHeadGATLayer(hidden_dim, hidden_dim, num_heads))
        self.out_dim = hidden_dim

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Forward pass.

        Args:
            x: (num_nodes, in_dim) node features.
            edge_index: (2, num_edges) edge indices.

        Returns:
            graph_embedding: (out_dim,) graph-level embedding.
            alpha: (num_edges, num_heads) attention weights from last layer.
        """
        h = x
        alpha = None
        for layer in self.layers:
            h, alpha = layer(h, edge_index)
            h = F.elu(h)

        # Readout: concat(mean, max, attention-weighted sum)
        mean_pool = h.mean(dim=0)
        max_pool = h.max(dim=0).values

        # Attention-weighted sum using last layer's attention
        if alpha is not None and edge_index.size(1) > 0:
            # Average attention across heads
            alpha_mean = alpha.mean(dim=-1)  # (num_edges,)
            src = edge_index[0]
            attn_sum = torch.zeros(h.size(1), device=h.device)
            msgs = h[src] * alpha_mean.unsqueeze(1)
            attn_sum.scatter_add_(0, src.unsqueeze(1).expand_as(msgs), msgs)
        else:
            attn_sum = h.sum(dim=0)

        graph_embedding = torch.cat([mean_pool, max_pool, attn_sum])
        return graph_embedding, alpha

    def get_attention_weights(
        self, x: torch.Tensor, edge_index: torch.Tensor
    ) -> torch.Tensor:
        """Get attention weights for visualization."""
        _, alpha = self.forward(x, edge_index)
        return alpha


def graph_embedding_dim(hidden_dim: int = 64) -> int:
    """Return the dimension of the graph embedding."""
    return hidden_dim * 3  # concat(mean, max, attn_sum)


def graph_forward(
    encoder: GATEncoder,
    graph: NetworkGraph,
) -> tuple[torch.Tensor, torch.Tensor]:
    """Convenience function to run GAT on a NetworkGraph.

    Returns:
        embedding: (out_dim,) graph embedding.
        alpha: attention weights.
    """
    x = torch.tensor(graph.node_features, dtype=torch.float32)
    edge_index = torch.tensor(graph.edge_index, dtype=torch.long)

    if x.size(0) == 0:
        return torch.zeros(encoder.out_dim * 3), torch.zeros(0)

    return encoder(x, edge_index)
