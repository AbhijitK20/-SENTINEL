"""Plotly graph builders used by the dashboard's attack-story views.

Colours come from the design tokens. Severity maps onto the risk ramp, so an
edge carrying attack traffic is read with the same colour language as a
probability, and the active/attacked path is drawn in the reserved "confirmed"
colour that sits outside the ramp.
"""

from __future__ import annotations

import math
from typing import Any

import networkx as nx
import plotly.graph_objects as go

from sentinel.frontend.tokens import color, plotly_layout

# Severity is a risk statement, so it wears the risk ramp.
SEVERITY_COLORS = {
    "normal": color("risk-quiet"),
    "medium": color("risk-concerning"),
    "high": color("risk-critical"),
    "critical": color("risk-severe"),
    "malicious": color("risk-severe"),
    "suspicious": color("risk-concerning"),
}
ACTIVE_COLOR = color("confirmed")
NODE_COLOR = color("accent")
NODE_BORDER = color("ink-muted")
TRANSITION_COLOR = color("insufficient")


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
        edge_color = SEVERITY_COLORS.get(str(edge.get("severity", "normal")), color("risk-quiet"))
        if edge.get("label") in active_labels:
            edge_color = ACTIVE_COLOR
        edge_traces.append(
            go.Scatter(
                x=[x1, x2, None],
                y=[y1, y2, None],
                mode="lines",
                line={
                    "width": max(1.5, math.log1p(float(edge.get("bytes", 1))) / 2),
                    "color": edge_color,
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
        marker={
            "size": node_sizes,
            "color": NODE_COLOR,
            "line": {"width": 1, "color": NODE_BORDER},
        },
        showlegend=False,
    )
    figure = go.Figure(data=[*edge_traces, node_trace])
    figure.update_layout(
        **plotly_layout(
            height=520,
            margin={"l": 10, "r": 10, "t": 20, "b": 10},
            xaxis={"visible": False},
            yaxis={"visible": False},
            hovermode="closest",
        )
    )
    return figure


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
                line={"width": 1 + 5 * probability, "color": TRANSITION_COLOR},
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
                "color": [ACTIVE_COLOR if node in active else NODE_COLOR for node in graph.nodes],
            },
            showlegend=False,
        )
    )
    figure = go.Figure(data=traces)
    figure.update_layout(
        **plotly_layout(
            height=460,
            margin={"l": 10, "r": 10, "t": 20, "b": 10},
            xaxis={"visible": False},
            yaxis={"visible": False},
        )
    )
    return figure
