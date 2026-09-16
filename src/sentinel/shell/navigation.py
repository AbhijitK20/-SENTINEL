# SPDX-License-Identifier: Apache-2.0
"""Navigation for SENTINEL shell."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NavigationItem:
    """Navigation item."""

    id: str
    label: str
    icon: str
    path: str
    shortcut: str = ""
    children: list[NavigationItem] | None = None


# Navigation structure
NAVIGATION: list[NavigationItem] = [
    NavigationItem(
        id="overview",
        label="Overview",
        icon="home",
        path="/",
        shortcut="go",
    ),
    NavigationItem(
        id="live",
        label="Live",
        icon="activity",
        path="/live",
        shortcut="gl",
    ),
    NavigationItem(
        id="forecasts",
        label="Forecasts",
        icon="trending-up",
        path="/forecasts",
        shortcut="gf",
    ),
    NavigationItem(
        id="investigate",
        label="Investigate",
        icon="search",
        path="/investigate",
        shortcut="gi",
    ),
    NavigationItem(
        id="entities",
        label="Entities",
        icon="users",
        path="/entities",
        shortcut="ge",
    ),
    NavigationItem(
        id="cases",
        label="Cases",
        icon="folder",
        path="/cases",
        shortcut="gc",
    ),
    NavigationItem(
        id="explain",
        label="Explain",
        icon="lightbulb",
        path="/explain",
        shortcut="gx",
    ),
    NavigationItem(
        id="models",
        label="Models",
        icon="cpu",
        path="/models",
        shortcut="gm",
    ),
    NavigationItem(
        id="data-sources",
        label="Data Sources",
        icon="database",
        path="/data-sources",
        shortcut="gd",
    ),
    NavigationItem(
        id="settings",
        label="Settings",
        icon="settings",
        path="/settings",
        shortcut="gs",
    ),
    NavigationItem(
        id="admin",
        label="Admin",
        icon="shield",
        path="/admin",
        shortcut="ga",
    ),
]


def get_navigation() -> list[NavigationItem]:
    """Get navigation items."""
    return NAVIGATION


def get_navigation_by_id(id: str) -> NavigationItem | None:
    """Get navigation item by ID."""
    for item in NAVIGATION:
        if item.id == id:
            return item
    return None


def get_shortcuts() -> dict[str, str]:
    """Get keyboard shortcuts mapping."""
    shortcuts: dict[str, str] = {}
    for item in NAVIGATION:
        if item.shortcut:
            shortcuts[item.shortcut] = item.path
    return shortcuts
