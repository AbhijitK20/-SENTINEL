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
    ColorToken("risk-quiet", "#45799F", "0.00–0.25 — cool, low bar"),
    ColorToken("risk-elevated", "#6FA0B8", "0.25–0.50 — cool-mid, bar height"),
    ColorToken("risk-concerning", "#C9B458", "0.50–0.75 — warm-mid, subtle border"),
    ColorToken("risk-critical", "#D98324", "0.75–0.90 — hot, border + icon"),
    ColorToken("risk-severe", "#CE4343", "0.90–1.00 — hottest"),
]

# Confirmed = ground truth / realised attack. Deliberately OUTSIDE the ramp
# so observed and forecast are never confusable.
CONFIRMED_COLOR = ColorToken("confirmed", "#C64B4B", "Ground truth / observed attack")

# Insufficient evidence = outside the ramp, hatched fill + reason text
INSUFFICIENT_COLOR = ColorToken("insufficient", "#667590", "Insufficient telemetry — NOT low risk")


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
# Prefixed `light-` on purpose: the dark and light sets describe the same roles,
# and sharing the names let the flattened palette silently overwrite dark values
# with light ones. Distinct names make that collision impossible.
CANVAS_LIGHT: list[ColorToken] = [
    ColorToken("light-bg-base", "#FAFAF8", "Lightest background"),
    ColorToken("light-bg-canvas", "#FFFFFF", "Light canvas"),
    ColorToken("light-bg-panel", "#F0F1EE", "Light panel / card surface"),
    ColorToken("light-bg-raised", "#E8E9E6", "Light raised element"),
    ColorToken("light-bg-hover", "#DDDEDB", "Light hover state"),
    ColorToken("light-bg-active", "#D2D3D0", "Light active / pressed state"),
    ColorToken("light-ink", "#14181E", "Primary text on light"),
]

# ── Ink (text) ──────────────────────────────────────────────────────────
INK: list[ColorToken] = [
    ColorToken("ink", "#E6E9EE", "Primary text (dark) / #14181E (light)"),
    ColorToken("ink-secondary", "#A0AAB8", "Secondary text"),
    ColorToken("ink-muted", "#8194AB", "Muted / tertiary text — AA on every surface"),
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
    ColorToken("success", "#45799F", "Success — uses risk-quiet (cool)"),
    ColorToken("warning", "#C9B458", "Warning — uses risk-concerning"),
    ColorToken("error", "#CE4343", "Error — uses risk-severe"),
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


def get_all_colors(theme: str = "dark") -> dict[str, str]:
    """Flatten the colour tokens into a name→value dict.

    ``theme`` picks the canvas layer set. Token names are unique across themes
    (light ones carry a ``light-`` prefix), so the result is unambiguous.
    """
    canvas = CANVAS_DARK if theme == "dark" else CANVAS_LIGHT
    if theme not in ("dark", "light"):
        raise ValueError(f"theme must be 'dark' or 'light', got {theme!r}")
    result: dict[str, str] = {}
    for token_list in [RISK_RAMP, canvas, INK, STRUCTURE, SEMANTIC, ACCENT]:
        for token in token_list:
            result[token.name] = token.value
    result["confirmed"] = CONFIRMED_COLOR.value
    result["insufficient"] = INSUFFICIENT_COLOR.value
    return result


def _token(token_list: list[ColorToken], name: str) -> str:
    for token in token_list:
        if token.name == name:
            return token.value
    raise KeyError(f"unknown design token: {name}")


# Band edges are the only place the ramp is interpreted. Colour bands match the
# ramp documentation exactly; RISK_BANDS must stay in sync with it.
RISK_BANDS: list[tuple[float, str]] = [
    (0.25, _token(RISK_RAMP, "risk-quiet")),
    (0.50, _token(RISK_RAMP, "risk-elevated")),
    (0.75, _token(RISK_RAMP, "risk-concerning")),
    (0.90, _token(RISK_RAMP, "risk-critical")),
]


def risk_color(probability: float) -> str:
    """Map a probability to the risk ramp colour. Colour is never the sole carrier."""
    value = min(max(float(probability), 0.0), 1.0)
    for edge, color in RISK_BANDS:
        if value < edge:
            return color
    return _token(RISK_RAMP, "risk-severe")


def risk_band(probability: float) -> str:
    """The ramp band *name* for a probability.

    Returned alongside the colour so every surface can carry a text label —
    colour is never the only carrier of meaning.
    """
    value = min(max(float(probability), 0.0), 1.0)
    for edge, name in [
        (0.25, "quiet"),
        (0.50, "elevated"),
        (0.75, "concerning"),
        (0.90, "critical"),
    ]:
        if value < edge:
            return name
    return "severe"


def color(name: str) -> str:
    """Look up any colour token by name, dark theme."""
    try:
        return _token(CANVAS_DARK, name)
    except KeyError:
        pass
    palette = get_all_colors()
    if name in palette:
        return palette[name]
    raise KeyError(f"unknown colour token: {name}")


def css_variables() -> dict[str, str]:
    """Every token as a CSS custom property, for the stylesheet injection.

    The values here are the *only* hex literals allowed in the frontend; the
    stylesheet and every component reference these names.
    """
    variables: dict[str, str] = {}
    for group in (RISK_RAMP, INK, STRUCTURE, SEMANTIC, ACCENT):
        for token in group:
            variables[f"--{token.name}"] = token.value
    for token in CANVAS_DARK:
        variables[f"--{token.name}"] = token.value
    variables["--confirmed"] = CONFIRMED_COLOR.value
    variables["--insufficient"] = INSUFFICIENT_COLOR.value
    for name, value in RADIUS.items():
        variables[f"--radius-{name}"] = value
    for name, value in SPACING.items():
        variables[f"--space-{name}"] = value
    for name, spec in TYPE_SCALE.items():
        variables[f"--type-{name}-size"] = spec["size"]
        variables[f"--type-{name}-line"] = spec["line-height"]
        variables[f"--type-{name}-weight"] = spec["weight"]
        variables[f"--type-{name}-tracking"] = spec["tracking"]
    for name, value in DENSITY.items():
        variables[f"--density-{name}"] = value
    for name, value in MOTION.items():
        variables[f"--motion-{name}"] = value
    return variables


def plotly_layout(**overrides) -> dict:
    """A Plotly layout that inherits the token palette.

    Every chart in the app starts from this so no figure hardcodes a background
    colour. Overrides win, which keeps per-chart tweaks local.
    """
    layout = {
        "template": "plotly_dark",
        "paper_bgcolor": color("bg-base"),
        "plot_bgcolor": color("bg-panel"),
        "font": {
            "family": '"Inter", "Segoe UI", system-ui, sans-serif',
            "size": 12,
            "color": color("ink-secondary"),
        },
        "colorway": [t.value for t in RISK_RAMP],
        "margin": {"l": 8, "r": 8, "t": 32, "b": 8},
        "hoverlabel": {
            "bgcolor": color("bg-raised"),
            "bordercolor": color("hairline-strong"),
            "font": {"color": color("ink"), "size": 12},
        },
        "xaxis": {
            "gridcolor": color("hairline"),
            "linecolor": color("hairline-strong"),
            "zerolinecolor": color("hairline"),
            "tickfont": {"color": color("ink-muted"), "size": 11},
        },
        "yaxis": {
            "gridcolor": color("hairline"),
            "linecolor": color("hairline-strong"),
            "zerolinecolor": color("hairline"),
            "tickfont": {"color": color("ink-muted"), "size": 11},
        },
        "legend": {
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.01,
            "x": 0,
            "font": {"color": color("ink-secondary"), "size": 11},
        },
    }
    layout.update(overrides)
    return layout


def streamlit_theme() -> dict[str, str]:
    """Token values for ``.streamlit/config.toml`` (Streamlit's own theme keys)."""
    return {
        "primaryColor": color("accent"),
        "backgroundColor": color("bg-base"),
        "secondaryBackgroundColor": color("bg-panel"),
        "textColor": color("ink"),
    }
