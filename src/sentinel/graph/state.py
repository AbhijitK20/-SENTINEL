# SPDX-License-Identifier: Apache-2.0
"""Network graph state — nodes are hosts, edges are directed host pairs.

Per window: nodes = hosts, edges = directed host pairs. Node features from
P1 computed per host. Edge features from flow summaries.

Identity must not leak. No one-hot IPs, no hostname embeddings.
Behavioural features plus is_internal only.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from sentinel.schemas import NetworkState


@dataclass
class NetworkGraph:
    """Graph representation of a network state window.

    Attributes:
        node_ids: Sorted host identifiers (deterministic ordering).
        node_features: (num_nodes, num_node_features) array.
        edge_index: (2, num_edges) array of [source_idx, target_idx].
        edge_features: (num_edges, num_edge_features) array.
        node_feature_names: Names for node feature columns.
        edge_feature_names: Names for edge feature columns.
    """

    node_ids: list[str]
    node_features: np.ndarray
    edge_index: np.ndarray
    edge_features: np.ndarray
    node_feature_names: list[str]
    edge_feature_names: list[str]

    @property
    def num_nodes(self) -> int:
        return len(self.node_ids)

    @property
    def num_edges(self) -> int:
        return self.edge_index.shape[1] if self.edge_index.size > 0 else 0


# Node features: behavioural per host
NODE_FEATURE_NAMES = [
    "fan_out",  # Number of distinct destinations
    "dst_port_entropy",  # Port diversity
    "dst_port_sequential_score",  # Scan pattern
    "flag_syn_ratio",  # SYN ratio
    "flag_ack_ratio",  # ACK ratio
    "failed_auth",  # Failed auth attempts
    "iat_mean",  # Mean inter-arrival time
    "iat_cv",  # IAT coefficient of variation
    "new_peer_count",  # New connections not seen before
    "is_internal",  # 1.0 if internal host, 0.0 otherwise
    "bytes_total",  # Total bytes sent
]

# Edge features: flow-level per directed host pair
EDGE_FEATURE_NAMES = [
    "flow_count",  # Number of flows
    "bytes_total",  # Total bytes
    "packets_total",  # Total packets
    "flag_syn_ratio",  # SYN ratio on this edge
    "ports_touched",  # Distinct ports used
    "is_new_edge",  # 1.0 if edge is new in this window
    "iat_mean",  # Mean IAT on this edge
]


def build_network_graph(
    state: NetworkState,
    known_hosts: set[str] | None = None,
) -> NetworkGraph:
    """Build a NetworkGraph from a NetworkState.

    Args:
        state: The network state window.
        known_hosts: Set of host IDs seen in previous windows (for new_peer_count).
            If None, all hosts are considered new.

    Returns:
        NetworkGraph with deterministic node ordering.
    """
    if not state.entities:
        return _empty_graph()

    # Deterministic node ordering
    node_ids = sorted(state.entities)
    node_idx = {host: i for i, host in enumerate(node_ids)}

    # Build node features
    node_features = np.zeros((len(node_ids), len(NODE_FEATURE_NAMES)), dtype=np.float32)
    for i, host in enumerate(node_ids):
        node_features[i] = _compute_node_features(host, state, known_hosts or set())

    # Build edge features from edge_summary
    edge_src = []
    edge_dst = []
    edge_feats = []

    for edge in state.edge_summary:
        src = edge["source"]
        dst = edge["destination"]
        if src in node_idx and dst in node_idx:
            edge_src.append(node_idx[src])
            edge_dst.append(node_idx[dst])
            edge_feats.append(_compute_edge_features(edge, state))

    if edge_src:
        edge_index = np.array([edge_src, edge_dst], dtype=np.int64)
        edge_features = np.array(edge_feats, dtype=np.float32)
    else:
        edge_index = np.zeros((2, 0), dtype=np.int64)
        edge_features = np.zeros((0, len(EDGE_FEATURE_NAMES)), dtype=np.float32)

    return NetworkGraph(
        node_ids=node_ids,
        node_features=node_features,
        edge_index=edge_index,
        edge_features=edge_features,
        node_feature_names=NODE_FEATURE_NAMES,
        edge_feature_names=EDGE_FEATURE_NAMES,
    )


def _compute_node_features(
    host: str, state: NetworkState, known_hosts: set[str]
) -> list[float]:
    """Compute node features for a single host."""
    features = state.features

    # Fan out: count distinct destinations from edge_summary
    destinations = set()
    for edge in state.edge_summary:
        if edge["source"] == host:
            destinations.add(edge["destination"])
    fan_out = float(len(destinations))

    # Port entropy
    dst_port_entropy = features.get("dst_port_entropy", 0.0)

    # Sequential score
    sequential_score = features.get("dst_port_sequential_score", 0.0)

    # Flag ratios
    flag_syn = features.get("flag_syn_ratio", 0.0)
    flag_ack = features.get("flag_ack_ratio", 0.0)

    # Failed auth
    failed_auth = features.get("failed_auth_sum", 0.0)

    # IAT
    iat_mean = features.get("iat_mean_mean", 0.0)
    iat_cv = features.get("iat_cv", 0.0)

    # New peer count
    new_peer_count = 0.0
    if known_hosts:
        for edge in state.edge_summary:
            if edge["source"] == host and edge["destination"] not in known_hosts:
                new_peer_count += 1.0

    # Is internal: simple heuristic (RFC 1918 or common internal ranges)
    is_internal = 1.0 if _is_internal_host(host) else 0.0

    # Bytes total
    bytes_total = 0.0
    for edge in state.edge_summary:
        if edge["source"] == host:
            bytes_total += edge.get("bytes", 0.0)

    return [
        fan_out,
        dst_port_entropy,
        sequential_score,
        flag_syn,
        flag_ack,
        failed_auth,
        iat_mean,
        iat_cv,
        new_peer_count,
        is_internal,
        bytes_total,
    ]


def _compute_edge_features(edge: dict, state: NetworkState) -> list[float]:
    """Compute edge features for a single directed host pair."""
    features = state.features

    return [
        edge.get("count", 0.0),
        edge.get("bytes", 0.0),
        0.0,  # packets_total (not in edge_summary yet)
        features.get("flag_syn_ratio", 0.0),
        0.0,  # ports_touched (computed separately)
        0.0,  # is_new_edge (computed separately)
        features.get("iat_mean_mean", 0.0),
    ]


def _is_internal_host(host: str) -> bool:
    """Check if a host is internal (RFC 1918 or common patterns)."""
    # Simple heuristic for now
    if host.startswith(("internal", "host-", "192.168.", "10.", "172.")):
        return True
    if host.startswith(("external", "1.2.3.4")):
        return False
    # Default: assume internal for unknown hosts
    return True


def _empty_graph() -> NetworkGraph:
    """Return an empty graph with zero nodes/edges."""
    return NetworkGraph(
        node_ids=[],
        node_features=np.zeros((0, len(NODE_FEATURE_NAMES)), dtype=np.float32),
        edge_index=np.zeros((2, 0), dtype=np.int64),
        edge_features=np.zeros((0, len(EDGE_FEATURE_NAMES)), dtype=np.float32),
        node_feature_names=NODE_FEATURE_NAMES,
        edge_feature_names=EDGE_FEATURE_NAMES,
    )
