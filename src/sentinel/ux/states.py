# SPDX-License-Identifier: Apache-2.0
"""UX states for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ViewState(Enum):
    """View states for components."""

    LOADING = "loading"
    EMPTY = "empty"
    ERROR = "error"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    NO_PERMISSION = "no_permission"
    READY = "ready"


@dataclass
class StateConfig:
    """Configuration for a view state."""

    state: ViewState
    title: str
    description: str
    action_label: str = ""
    action_url: str = ""


# State configurations
STATE_CONFIGS: dict[ViewState, StateConfig] = {
    ViewState.LOADING: StateConfig(
        state=ViewState.LOADING,
        title="Loading",
        description="Fetching data...",
    ),
    ViewState.EMPTY: StateConfig(
        state=ViewState.EMPTY,
        title="No data",
        description="No data available yet. Connect a data source or load sample data.",
        action_label="Connect Data Source",
        action_url="/data-sources",
    ),
    ViewState.ERROR: StateConfig(
        state=ViewState.ERROR,
        title="Error",
        description="Something went wrong. Please try again or contact support.",
        action_label="Retry",
    ),
    ViewState.PARTIAL: StateConfig(
        state=ViewState.PARTIAL,
        title="Partial data",
        description="Some data sources are unavailable.",
        action_label="View Status",
        action_url="/data-sources",
    ),
    ViewState.DEGRADED: StateConfig(
        state=ViewState.DEGRADED,
        title="Reduced fidelity",
        description="Detection sensitivity reduced due to system load.",
    ),
    ViewState.NO_PERMISSION: StateConfig(
        state=ViewState.NO_PERMISSION,
        title="Access required",
        description="You don't have permission to view this page.",
        action_label="Request Access",
    ),
    ViewState.READY: StateConfig(
        state=ViewState.READY,
        title="",
        description="",
    ),
}


def get_state_config(state: ViewState) -> StateConfig:
    """Get configuration for a view state."""
    return STATE_CONFIGS.get(state, STATE_CONFIGS[ViewState.READY])
