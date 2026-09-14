"""Plotly graph builders used by the dashboard's attack-story views."""

from __future__ import annotations

import math
from typing import Any

import networkx as nx
import plotly.graph_objects as go

SEVERITY_COLORS = {
    "normal": "#64748b",
    "medium": "#f59e0b",
    "high": "#f97316",
    "critical": "#ef4444",
    "malicious": "#ef4444",
    "suspicious": "#f59e0b",
}


def topology_figure(
    nodes: dict[str, str],
    edges: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    active_labels: set[str] | None = None,
) -> go.Figure:
    """Build a deterministic node-link topology figure."""
    graph = nx.Graph()
    graph.add_nodes_from(nodes)
    graph.add_edges_from((edge["source"], edge["destination"]) for edge in edges)
    positions = nx.spring_layout(graph, seed=42, k=1.2)
    active_labels = active_labels or set()

    edge_traces: list[go.Scatter] = []
    for edge in edges:
        x1, y1 = positions[edge["source"]]
        x2, y2 = positions[edge["destination"]]
        color = SEVERITY_COLORS.get(str(edge.get("severity", "normal")), "#64748b")
        if edge.get("label") in active_labels:
            color = "#ef4444"
        edge_traces.append(
            go.Scatter(
                x=[x1, x2, None],
                y=[y1, y2, None],
                mode="lines",
                line={
                    "width": max(1.5, math.log1p(float(edge.get("bytes", 1))) / 2),
                    "color": color,
                },
                hoverinfo="text",
                text=(
                    f"{edge['label']} · {edge['protocol']}:{edge['port']} · "
                    f"{edge['bytes']:,.0f} bytes"
                ),
                showlegend=False,
            )
        )

    node_x = [positions[node][0] for node in nodes]
    node_y = [positions[node][1] for node in nodes]
    node_sizes = [24 if "database" in node else 20 if "attacker" in node else 16 for node in nodes]
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=list(nodes),
        textposition="bottom center",
        hovertext=[nodes[node] for node in nodes],
        hoverinfo="text",
        marker={"size": node_sizes, "color": "#3b82f6", "line": {"width": 1, "color": "#e2e8f0"}},
        showlegend=False,
    )
    fig = go.Figure(data=[*edge_traces, node_trace])
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=520,
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        xaxis={"visible": False},
        yaxis={"visible": False},
        hovermode="closest",
    )
    return fig


def kill_chain_figure(
    transitions: dict[str, dict[str, float]],
    active: set[str] | None = None,
) -> go.Figure:
    """Build a directed attack-transition graph with active-node emphasis."""
    active = active or set()
    graph = nx.DiGraph()
    for source, targets in transitions.items():
        for target, probability in targets.items():
            graph.add_edge(source, target, probability=probability)
    positions = nx.spring_layout(graph, seed=7, k=1.5)
    traces: list[go.Scatter] = []
    for source, target, data in graph.edges(data=True):
        x1, y1 = positions[source]
        x2, y2 = positions[target]
        probability = float(data["probability"])
        traces.append(
            go.Scatter(
                x=[x1, x2, None],
                y=[y1, y2, None],
                mode="lines",
                line={"width": 1 + 5 * probability, "color": "#8b5cf6"},
                hoverinfo="text",
                text=f"{source} -> {target}: {probability:.0%}",
                showlegend=False,
            )
        )
    traces.append(
        go.Scatter(
            x=[positions[node][0] for node in graph.nodes],
            y=[positions[node][1] for node in graph.nodes],
            mode="markers+text",
            text=list(graph.nodes),
            textposition="bottom center",
            hoverinfo="text",
            hovertext=["ACTIVE" if node in active else "transition node" for node in graph.nodes],
            marker={
                "size": [28 if node in active else 18 for node in graph.nodes],
                "color": ["#ef4444" if node in active else "#3b82f6" for node in graph.nodes],
            },
            showlegend=False,
        )
    )
    fig = go.Figure(data=traces)
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=460,
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        xaxis={"visible": False},
        yaxis={"visible": False},
    )
    return fig
