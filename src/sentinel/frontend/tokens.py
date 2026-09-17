# SPDX-License-Identifier: Apache-2.0
"""Design tokens for SENTINEL — derived from the product's subject matter, not from fashion.

The subject is time and probability. A defender watching a network at 3 a.m.,
needing to decide within seconds whether something is happening.

Design rules (§4.1):
1. Observed and forecast are never confusable.
2. Insufficient evidence is not low risk.
3. Only probability is bright — chrome is neutral.
4. Every number names its method.
5. Time is shared — one time context across the whole application.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ColorToken:
    """Semantic colour token. Name encodes purpose, not hue."""

    name: str
    value: str
    description: str = ""


# ── Risk ramp — the one thing to get exactly right ──────────────────────
# Perceptually uniform sequential ramp: cool → warm → hot.
# Maps monotonically to P(infiltration). Colour is never the sole carrier.
RISK_RAMP: list[ColorToken] = [
    ColorToken("risk-quiet", "#3E6C8E", "0.00–0.25 — cool, low bar"),
    ColorToken("risk-elevated", "#6FA0B8", "0.25–0.50 — cool-mid, bar height"),
    ColorToken("risk-concerning", "#C9B458", "0.50–0.75 — warm-mid, subtle border"),
    ColorToken("risk-critical", "#D98324", "0.75–0.90 — hot, border + icon"),
    ColorToken("risk-severe", "#B33A3A", "0.90–1.00 — hottest"),
]

# Confirmed = ground truth / realised attack. Deliberately OUTSIDE the ramp
# so observed and forecast are never confusable.
CONFIRMED_COLOR = ColorToken("confirmed", "#7A2E2E", "Ground truth / observed attack")

# Insufficient evidence = outside the ramp, hatched fill + reason text
INSUFFICIENT_COLOR = ColorToken("insufficient", "#4A5568", "Insufficient telemetry — NOT low risk")


# ── Canvas layers (dark theme — the primary product theme) ──────────────
CANVAS_DARK: list[ColorToken] = [
    ColorToken("bg-base", "#0E1116", "Deepest background"),
    ColorToken("bg-canvas", "#161A21", "Main canvas"),
    ColorToken("bg-panel", "#1E242D", "Panel / card surface"),
    ColorToken("bg-raised", "#262C36", "Raised element (dropdown, popover)"),
    ColorToken("bg-hover", "#2D3544", "Hover state on interactive surfaces"),
    ColorToken("bg-active", "#354052", "Active / pressed state"),
]

# ── Canvas layers (light theme) ─────────────────────────────────────────
CANVAS_LIGHT: list[ColorToken] = [
    ColorToken("bg-base", "#FAFAF8", "Lightest background"),
    ColorToken("bg-canvas", "#FFFFFF", "Main canvas"),
    ColorToken("bg-panel", "#F0F1EE", "Panel / card surface"),
    ColorToken("bg-raised", "#E8E9E6", "Raised element"),
    ColorToken("bg-hover", "#DDDEDB", "Hover state"),
    ColorToken("bg-active", "#D2D3D0", "Active / pressed state"),
]

# ── Ink (text) ──────────────────────────────────────────────────────────
INK: list[ColorToken] = [
    ColorToken("ink", "#E6E9EE", "Primary text (dark) / #14181E (light)"),
    ColorToken("ink-secondary", "#A0AAB8", "Secondary text"),
    ColorToken("ink-muted", "#6B7A8D", "Muted / tertiary text"),
    ColorToken("ink-disabled", "#4A5568", "Disabled text"),
]

# ── Structure ───────────────────────────────────────────────────────────
STRUCTURE: list[ColorToken] = [
    ColorToken("hairline", "#262C36", "1px dividers — never a shadow"),
    ColorToken("hairline-strong", "#3A4354", "Emphasised divider"),
    ColorToken("focus-ring", "#6FA0B8", "Keyboard focus indicator — matches risk-elevated"),
]

# ── Semantic ────────────────────────────────────────────────────────────
SEMANTIC: list[ColorToken] = [
    ColorToken("success", "#3E6C8E", "Success — uses risk-quiet (cool)"),
    ColorToken("warning", "#C9B458", "Warning — uses risk-concerning"),
    ColorToken("error", "#B33A3A", "Error — uses risk-severe"),
    ColorToken("info", "#6FA0B8", "Info — uses risk-elevated"),
]

# ── Accent — deliberately restrained ────────────────────────────────────
# Only used for interactive elements that need to stand out from the
# neutral chrome. Never competing with the risk ramp.
ACCENT: list[ColorToken] = [
    ColorToken("accent", "#6FA0B8", "Interactive accent — matches risk-elevated"),
    ColorToken("accent-hover", "#8BB8CC", "Accent hover"),
    ColorToken("accent-active", "#5A8FA6", "Accent active"),
    ColorToken("accent-subtle", "#1A2A36", "Accent background wash"),
]


# ── Spacing (4px base, 8px rhythm) ─────────────────────────────────────
SPACING: dict[str, str] = {
    "0": "0px",
    "0.5": "2px",
    "1": "4px",
    "1.5": "6px",
    "2": "8px",
    "3": "12px",
    "4": "16px",
    "5": "20px",
    "6": "24px",
    "8": "32px",
    "10": "40px",
    "12": "48px",
    "16": "64px",
    "20": "80px",
}


# ── Radii — two values only, to encode hierarchy ────────────────────────
# radius-sm for small elements (badges, chips), radius-lg for cards/panels.
# A product that uses one radius everywhere reads as templated.
RADIUS: dict[str, str] = {
    "sm": "4px",
    "lg": "8px",
}


# ── Typography ──────────────────────────────────────────────────────────
# One grotesque family with tight apertures + one mono for numeric alignment.
# Five sizes, no more. Mono only where it does real work (tables, hex, IPs).
TYPE_SCALE: dict[str, dict[str, str]] = {
    "display": {"size": "28px", "line-height": "32px", "tracking": "-0.01em", "weight": "700"},
    "section": {"size": "20px", "line-height": "28px", "tracking": "-0.01em", "weight": "600"},
    "body": {"size": "14px", "line-height": "20px", "tracking": "0em", "weight": "400"},
    "data": {
        "size": "13px",
        "line-height": "18px",
        "tracking": "0em",
        "weight": "400",
        "font": "mono",
    },
    "label": {"size": "12px", "line-height": "16px", "tracking": "+0.01em", "weight": "500"},
    "micro": {"size": "11px", "line-height": "14px", "tracking": "+0.01em", "weight": "500"},
}


# ── Elevation — borders and background steps, not soft shadows ──────────
# Shadows on dark UI look muddy. Use borders + bg steps for depth.
ELEVATION: dict[str, dict[str, str]] = {
    "none": {"border": "none", "bg": "bg-base"},
    "flat": {"border": "1px solid #262C36", "bg": "bg-canvas"},
    "raised": {"border": "1px solid #3A4354", "bg": "bg-panel"},
    "overlay": {"border": "1px solid #3A4354", "bg": "bg-raised"},
}


# ── Motion ──────────────────────────────────────────────────────────────
# Exactly one orchestrated moment: new alert arrival.
# Everything else answers actions. Respect prefers-reduced-motion.
MOTION: dict[str, str] = {
    "duration-micro": "100ms",
    "duration-fast": "150ms",
    "duration-normal": "200ms",
    "duration-slow": "300ms",
    "duration-page": "400ms",
    "easing-in": "cubic-bezier(0.4, 0, 1, 1)",
    "easing-out": "cubic-bezier(0, 0, 0.2, 1)",
    "easing-in-out": "cubic-bezier(0.4, 0, 0.2, 1)",
    "easing-spring": "cubic-bezier(0.34, 1.56, 0.64, 1)",
}


# ── Density ─────────────────────────────────────────────────────────────
# Default to compact — 28px table rows, 8px base.
# Analysts want more rows visible, not more air.
DENSITY: dict[str, str] = {
    "table-row-height": "28px",
    "input-height": "32px",
    "button-height": "32px",
    "nav-item-height": "36px",
}


def get_all_colors() -> dict[str, str]:
    """Flatten all colour tokens into a name→value dict."""
    result: dict[str, str] = {}
    for token_list in [RISK_RAMP, CANVAS_DARK, CANVAS_LIGHT, INK, STRUCTURE, SEMANTIC, ACCENT]:
        for t in token_list:
            result[t.name] = t.value
    result["confirmed"] = CONFIRMED_COLOR.value
    result["insufficient"] = INSUFFICIENT_COLOR.value
    return result


def risk_color(probability: float) -> str:
    """Map a probability to the risk ramp colour. Colour is never the sole carrier."""
    if probability < 0.25:
        return "#3E6C8E"
    if probability < 0.50:
        return "#6FA0B8"
    if probability < 0.75:
        return "#C9B458"
    if probability < 0.90:
        return "#D98324"
    return "#B33A3A"
