# SPDX-License-Identifier: Apache-2.0
"""Design tokens for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ColorToken:
    """Color token."""

    name: str
    value: str
    description: str = ""


@dataclass
class SpacingToken:
    """Spacing token."""

    name: str
    value: str
    description: str = ""


@dataclass
class RadiusToken:
    """Radius token."""

    name: str
    value: str
    description: str = ""


@dataclass
class ElevationToken:
    """Elevation token."""

    name: str
    value: str
    description: str = ""


@dataclass
class TypeToken:
    """Type token."""

    name: str
    value: str
    description: str = ""


@dataclass
class MotionToken:
    """Motion token."""

    name: str
    value: str
    description: str = ""


# Color tokens (semantic, not literal)
COLORS: list[ColorToken] = [
    ColorToken("risk-high", "#ef4444", "High risk"),
    ColorToken("risk-medium", "#f59e0b", "Medium risk"),
    ColorToken("risk-low", "#22c55e", "Low risk"),
    ColorToken("risk-unknown", "#6b7280", "Unknown risk"),
    ColorToken("risk-insufficient", "#9ca3af", "Insufficient evidence"),
    ColorToken("text-primary", "#f9fafb", "Primary text"),
    ColorToken("text-secondary", "#d1d5db", "Secondary text"),
    ColorToken("text-muted", "#9ca3af", "Muted text"),
    ColorToken("bg-primary", "#111827", "Primary background"),
    ColorToken("bg-secondary", "#1f2937", "Secondary background"),
    ColorToken("bg-tertiary", "#374151", "Tertiary background"),
    ColorToken("border-primary", "#374151", "Primary border"),
    ColorToken("border-secondary", "#4b5563", "Secondary border"),
    ColorToken("accent", "#3b82f6", "Accent color"),
    ColorToken("success", "#22c55e", "Success color"),
    ColorToken("warning", "#f59e0b", "Warning color"),
    ColorToken("error", "#ef4444", "Error color"),
]

# Spacing tokens (4px base, 8px rhythm)
SPACING: list[SpacingToken] = [
    SpacingToken("0", "0px", "No spacing"),
    SpacingToken("1", "4px", "Extra small"),
    SpacingToken("2", "8px", "Small"),
    SpacingToken("3", "12px", "Medium small"),
    SpacingToken("4", "16px", "Medium"),
    SpacingToken("5", "20px", "Medium large"),
    SpacingToken("6", "24px", "Large"),
    SpacingToken("8", "32px", "Extra large"),
    SpacingToken("10", "40px", "2x large"),
    SpacingToken("12", "48px", "3x large"),
    SpacingToken("16", "64px", "4x large"),
]

# Radius tokens (two values only)
RADIUS: list[RadiusToken] = [
    RadiusToken("sm", "4px", "Small radius"),
    RadiusToken("lg", "8px", "Large radius"),
]

# Elevation tokens (borders and background steps)
ELEVATION: list[ElevationToken] = [
    ElevationToken("none", "none", "No elevation"),
    ElevationToken("sm", "0 1px 2px 0 rgba(0, 0, 0, 0.05)", "Small elevation"),
    ElevationToken("md", "0 4px 6px -1px rgba(0, 0, 0, 0.1)", "Medium elevation"),
    ElevationToken("lg", "0 10px 15px -3px rgba(0, 0, 0, 0.1)", "Large elevation"),
]

# Type tokens
TYPE: list[TypeToken] = [
    TypeToken("xs", "12px", "Extra small text"),
    TypeToken("sm", "14px", "Small text"),
    TypeToken("base", "16px", "Base text"),
    TypeToken("lg", "18px", "Large text"),
    TypeToken("xl", "20px", "Extra large text"),
    TypeToken("2xl", "24px", "2x large text"),
    TypeToken("3xl", "30px", "3x large text"),
]

# Motion tokens
MOTION: list[MotionToken] = [
    MotionToken("duration-fast", "100ms", "Fast duration"),
    MotionToken("duration-normal", "200ms", "Normal duration"),
    MotionToken("duration-slow", "300ms", "Slow duration"),
    MotionToken("easing-default", "ease-in-out", "Default easing"),
    MotionToken("easing-in", "ease-in", "In easing"),
    MotionToken("easing-out", "ease-out", "Out easing"),
]


def get_color(name: str) -> str:
    """Get color value by name."""
    for color in COLORS:
        if color.name == name:
            return color.value
    return "#000000"


def get_spacing(name: str) -> str:
    """Get spacing value by name."""
    for spacing in SPACING:
        if spacing.name == name:
            return spacing.value
    return "0px"


def get_radius(name: str) -> str:
    """Get radius value by name."""
    for radius in RADIUS:
        if radius.name == name:
            return radius.value
    return "0px"


def get_elevation(name: str) -> str:
    """Get elevation value by name."""
    for elevation in ELEVATION:
        if elevation.name == name:
            return elevation.value
    return "none"


def get_type(name: str) -> str:
    """Get type value by name."""
    for type_token in TYPE:
        if type_token.name == name:
            return type_token.value
    return "16px"


def get_motion(name: str) -> str:
    """Get motion value by name."""
    for motion in MOTION:
        if motion.name == name:
            return motion.value
    return "200ms"
