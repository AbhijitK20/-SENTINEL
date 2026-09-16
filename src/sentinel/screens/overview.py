# SPDX-License-Identifier: Apache-2.0
"""Overview screen for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskTrajectory:
    """Risk trajectory data for overview."""

    timestamps: list[str]
    risk_scores: list[float]
    uncertainty_lower: list[float]
    uncertainty_upper: list[float]
    threshold: float
    forecast_horizon: list[str]
    forecast_scores: list[float]


@dataclass
class EntityAtRisk:
    """Entity at risk data for overview."""

    entity_id: str
    risk_score: float
    stage: str
    trend: str  # "up", "down", "stable"
    sparkline: list[float]


@dataclass
class OpenIncident:
    """Open incident data for overview."""

    id: str
    title: str
    priority: str
    status: str
    created_at: str
    sla_deadline: str
    assignee: str


def get_overview_data() -> dict:
    """Get overview screen data.

    Returns:
        Dictionary with risk trajectory, entities at risk, and open incidents.
    """
    return {
        "risk_trajectory": RiskTrajectory(
            timestamps=[],
            risk_scores=[],
            uncertainty_lower=[],
            uncertainty_upper=[],
            threshold=0.85,
            forecast_horizon=[],
            forecast_scores=[],
        ),
        "entities_at_risk": [],
        "open_incidents": [],
    }
