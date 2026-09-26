# SPDX-License-Identifier: Apache-2.0
"""``sentinel.frontend.ui`` — the short name screens import.

Re-exports the component library so a screen module reads as layout and copy
rather than as a list of styling calls. Nothing new lives here.
"""

from __future__ import annotations

from sentinel.frontend.components import (
    Stat,
    banner,
    degraded,
    empty,
    end_panel,
    evidence,
    grouped_bars,
    header,
    insufficient,
    lede,
    method_note,
    observed_forecast_legend,
    panel,
    probability_timeline,
    ramp,
    risk_meter,
    risk_over_time,
    skeleton,
    sparkline,
    stage_badge,
    stats,
    time_spine,
)
from sentinel.frontend.tokens import risk_band


def band_of(probability: float | None) -> str | None:
    """The risk-ramp band name for a value, or ``None`` when there is no value.

    Passing the band (not just the colour) is what keeps a stat tile readable
    without relying on its accent colour.
    """
    if probability is None:
        return None
    return risk_band(probability)


__all__ = [
    "Stat",
    "band_of",
    "banner",
    "degraded",
    "empty",
    "end_panel",
    "evidence",
    "grouped_bars",
    "header",
    "insufficient",
    "lede",
    "method_note",
    "observed_forecast_legend",
    "panel",
    "probability_timeline",
    "ramp",
    "risk_meter",
    "risk_over_time",
    "skeleton",
    "sparkline",
    "stage_badge",
    "stats",
    "time_spine",
]
