# SPDX-License-Identifier: Apache-2.0
"""The SENTINEL component library.

Every component here takes data, not styling decisions: colours come from
:mod:`sentinel.frontend.tokens`, spacing and type from the stylesheet, so a
screen can never invent a colour or a radius.

Each interactive surface defines the four states (hover, active, focus-visible,
disabled) in CSS, carries a skeleton and an empty state, and pairs every colour
with a text label — colour is never the only carrier of meaning, which matters
most for the risk ramp.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import plotly.graph_objects as go
import streamlit as st

from sentinel.frontend.theme import esc, ramp_legend
from sentinel.frontend.tokens import color, plotly_layout, risk_band, risk_color

BannerTone = Literal["degraded", "error", "info", "insufficient"]


# ── Shell ───────────────────────────────────────────────────────────────


def header(title: str, subtitle: str, meta: str = "") -> None:
    """App header: identity on the left, dataset identity on the right."""
    st.markdown(
        f"""
<div class="sntl-header">
  <span class="sntl-header__mark">{esc(title)}</span>
  <span class="sntl-header__sub">{esc(subtitle)}</span>
  <span class="sntl-header__spacer"></span>
  <span class="sntl-header__meta">{esc(meta)}</span>
</div>
""",
        unsafe_allow_html=True,
    )


def lede(text: str) -> None:
    """One-paragraph orientation for a screen. Long screens state their method."""
    st.markdown(f'<p class="sntl-lede">{esc(text)}</p>', unsafe_allow_html=True)


def method_note(text: str) -> None:
    """How a number was produced. Every surface that shows a number needs one."""
    st.markdown(f'<p class="sntl-method">{esc(text)}</p>', unsafe_allow_html=True)


def panel(title: str, hint: str = "") -> None:
    """Open a titled panel. Returns a context manager closing the div."""
    hint_html = f'<p class="sntl-panel__hint">{esc(hint)}</p>' if hint else ""
    st.markdown(
        f'<div class="sntl-panel"><p class="sntl-panel__title">{esc(title)}</p>{hint_html}',
        unsafe_allow_html=True,
    )


def end_panel() -> None:
    """Close a panel opened by :func:`panel`."""
    st.markdown("</div>", unsafe_allow_html=True)


# ── Statistics ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Stat:
    """One labelled number. ``band`` links the value to the risk ramp."""

    label: str
    value: str
    note: str = ""
    band: str | None = None


def stats(items: Sequence[Stat]) -> None:
    """A responsive grid of stat tiles (2 columns on mobile, auto-fit above)."""
    if not items:
        empty("No measurements", "This surface has nothing to report yet.")
        return
    cells = []
    for item in items:
        modifier = f" sntl-stat--{item.band}" if item.band else " sntl-stat--neutral"
        note = f'<div class="sntl-stat__note">{esc(item.note)}</div>' if item.note else ""
        cells.append(
            f'<div class="sntl-stat{modifier}">'
            f'<div class="sntl-stat__label">{esc(item.label)}</div>'
            f'<div class="sntl-stat__value">{esc(item.value)}</div>'
            f"{note}</div>"
        )
    st.markdown(f'<div class="sntl-stats">{"".join(cells)}</div>', unsafe_allow_html=True)


def risk_meter(
    probability: float,
    *,
    label: str = "P(infiltration)",
    threshold: float | None = None,
    spread: float | None = None,
    note: str = "",
) -> None:
    """Probability with an explicit numeral, band label, and uncertainty band.

    ``spread`` is the between-sample standard deviation from imagination; when
    present the band is drawn so the analyst sees the model's own uncertainty
    rather than a single falsely precise number.
    """
    value = min(max(float(probability), 0.0), 1.0)
    band = risk_band(value)
    fill = f"width: {value * 100:.1f}%; background: {risk_color(value)};"
    bands = "".join(
        f'<span class="sntl-meter__band" style="left: {edge * 100:.0f}%;"></span>'
        for edge in (0.25, 0.5, 0.75, 0.9)
    )
    threshold_mark = (
        f'<span class="sntl-meter__threshold" style="left: {threshold * 100:.1f}%;"></span>'
        if threshold is not None
        else ""
    )
    foot = ""
    if spread is not None:
        low = min(max(value - spread, 0.0), 1.0)
        high = min(max(value + spread, 0.0), 1.0)
        foot = (
            f"<span>model spread {low:.2f}–{high:.2f}</span>"
            f"<span class='sntl-meter__band-label'>{esc(band)}</span>"
        )
    elif note:
        foot = f"<span>{esc(note)}</span><span></span>"
    if threshold is not None and not foot:
        foot = f"<span>threshold {threshold:.2f}</span><span></span>"
    st.markdown(
        f"""
<div class="sntl-meter">
  <div class="sntl-meter__head">
    <span class="sntl-meter__label">{esc(label)}</span>
    <span class="sntl-meter__value" style="color: {risk_color(value)};">{value:.3f}</span>
  </div>
  <div class="sntl-meter__track">
    <span class="sntl-meter__fill" style="{fill}"></span>
    {bands}
    {threshold_mark}
  </div>
  <div class="sntl-meter__foot">{foot}</div>
</div>
""",
        unsafe_allow_html=True,
    )
    if note and spread is None:
        method_note(note)


def ramp() -> None:
    """Risk ramp legend. Shown once per screen that encodes probability."""
    st.markdown(ramp_legend(), unsafe_allow_html=True)


# ── Status ──────────────────────────────────────────────────────────────


def stage_badge(
    name: str,
    confidence: str = "",
    mitre: str | None = None,
    probability: float | None = None,
) -> None:
    """Attack stage with its confidence word and MITRE reference.

    Confidence is a word, not a number, because the underlying value is a
    calibrated bucket rather than a probability.
    """
    dot = risk_color(probability) if probability is not None else color("accent")
    conf = f'<span class="sntl-stage__conf">{esc(confidence)}</span>' if confidence else ""
    reference = f'<span class="sntl-stage__conf">{esc(mitre)}</span>' if mitre else ""
    modifier = " sntl-stage--mitre" if mitre else ""
    st.markdown(
        f'<span class="sntl-stage{modifier}">'
        f'<span class="sntl-stage__dot" style="background: {dot};"></span>'
        f"{esc(name)}{conf}{reference}</span>",
        unsafe_allow_html=True,
    )


def banner(
    title: str,
    body: str = "",
    tone: BannerTone = "info",
    icon: str = "›",
) -> None:
    """Degraded-capability, error, and insufficient-evidence surfaces.

    ``insufficient`` is deliberately not a risk colour: "we did not measure this"
    and "this is low risk" must never look alike.
    """
    st.markdown(
        f"""
<div class="sntl-banner sntl-banner--{tone}">
  <span class="sntl-banner__icon">{esc(icon)}</span>
  <div>
    <p class="sntl-banner__title">{esc(title)}</p>
    <p class="sntl-banner__body">{esc(body)}</p>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def degraded(what: str, consequence: str) -> None:
    """The honest "we are running without X" surface."""
    banner(f"Degraded: {what}", consequence, tone="degraded", icon="!")


def insufficient(what: str) -> None:
    """Insufficient telemetry — explicitly not a low-risk reading."""
    banner(
        f"Insufficient evidence: {what}",
        "No measurement supports a stage hypothesis here. This is not a low-risk reading.",
        tone="insufficient",
        icon="–",
    )


# ── Evidence ────────────────────────────────────────────────────────────


def evidence(
    items: Sequence[tuple[str, str]],
    directions: Sequence[str] | None = None,
) -> None:
    """Feature evidence behind a claim: name, value, direction.

    ``directions`` is parallel to ``items``; "up" means the feature raises risk.
    """
    if not items:
        empty("No evidence", "No documented rule fired on this window.")
        return
    rows = []
    for index, (name, value) in enumerate(items):
        direction = directions[index] if directions and index < len(directions) else ""
        modifier = ""
        if direction in ("up", "increasing"):
            modifier = " sntl-evidence__dir--up"
        elif direction in ("down", "decreasing"):
            modifier = " sntl-evidence__dir--down"
        dir_html = (
            f'<span class="sntl-evidence__dir{modifier}">{esc(direction)}</span>'
            if direction
            else ""
        )
        rows.append(
            f'<div class="sntl-evidence__item">'
            f"<span>{esc(name)}</span>"
            f'<span class="sntl-evidence__value">{esc(value)} {dir_html}</span>'
            f"</div>"
        )
    st.markdown(f'<div class="sntl-evidence">{"".join(rows)}</div>', unsafe_allow_html=True)


# ── Time ────────────────────────────────────────────────────────────────


def time_spine(
    labels: Sequence[str],
    *,
    split_index: int,
    attack: Sequence[bool] | None = None,
) -> None:
    """The shared time axis: observed on the left, forecast on the right.

    Every screen that shows a trajectory renders this in the same position and
    the same scale, so moving time in one place moves it everywhere.
    """
    ticks = []
    for index, label in enumerate(labels):
        if attack is not None and index < len(attack) and attack[index]:
            modifier = " sntl-spine__tick--attack"
        elif index < split_index:
            modifier = " sntl-spine__tick--observed"
        else:
            modifier = " sntl-spine__tick--forecast"
        ticks.append(
            f'<div class="sntl-spine__tick{modifier}">'
            f'<div class="sntl-spine__tick-label">{esc(label)}</div>'
            f'<div class="sntl-spine__bar"></div></div>'
        )
    st.markdown(f'<div class="sntl-spine">{"".join(ticks)}</div>', unsafe_allow_html=True)


def observed_forecast_legend(note: str = "") -> None:
    """Persistent strip: what is measured versus what is simulated."""
    tail = f'<span class="sntl-legend__note">{esc(note)}</span>' if note else ""
    st.markdown(
        f"""
<div class="sntl-legend">
  <span class="sntl-legend__item">
    <span class="sntl-legend__swatch sntl-legend__swatch--observed"></span>
    Observed — measured from telemetry
  </span>
  <span class="sntl-legend__item">
    <span class="sntl-legend__swatch sntl-legend__swatch--forecast"></span>
    Forecast — simulated, not measured
  </span>
  {tail}
</div>
""",
        unsafe_allow_html=True,
    )


# ── States ──────────────────────────────────────────────────────────────


def empty(title: str, body: str = "", icon: str = "◌") -> None:
    """Empty state: icon + heading, plus an explanation when there is one."""
    body_html = f'<p class="sntl-empty__body">{esc(body)}</p>' if body else ""
    st.markdown(
        f"""
<div class="sntl-empty">
  <span class="sntl-empty__icon">{esc(icon)}</span>
  <p class="sntl-empty__title">{esc(title)}</p>
  {body_html}
</div>
""",
        unsafe_allow_html=True,
    )


def skeleton(rows: int = 3) -> None:
    """Loading placeholder whose geometry matches a stat grid + panel."""
    cell = '<div class="sntl-skeleton"></div>'
    st.markdown(
        f'<div class="sntl-stats">{cell * min(rows, 4)}</div>',
        unsafe_allow_html=True,
    )


# ── Charts ──────────────────────────────────────────────────────────────


def probability_timeline(
    windows: Sequence[int],
    probabilities: Sequence[float],
    *,
    threshold: float,
    confidences: Sequence[float] | None = None,
    realized: Sequence[bool] | None = None,
    height: int = 320,
) -> None:
    """Forecast probability over the horizon, with the decision threshold.

    The realised outcome is drawn in the "confirmed" colour, which sits outside
    the risk ramp so a forecast can never be mistaken for an observation.
    """
    figure = go.Figure()
    figure.add_trace(
        go.Scatter(
            x=list(windows),
            y=list(probabilities),
            name="Forecast P(infiltration)",
            mode="lines+markers",
            line={"color": color("accent"), "width": 2},
            marker={"size": 6},
        )
    )
    if confidences is not None and len(confidences) == len(probabilities):
        figure.add_trace(
            go.Scatter(
                x=list(windows),
                y=[max(p - c * 0.1, 0.0) for p, c in zip(probabilities, confidences, strict=True)],
                name="Lower bound (1 − confidence)",
                mode="lines",
                line={"color": color("accent"), "width": 1, "dash": "dot"},
            )
        )
    if realized is not None and len(realized) == len(windows):
        figure.add_trace(
            go.Scatter(
                x=list(windows),
                y=[1.0 if flag else 0.0 for flag in realized],
                name="Realised (observed)",
                mode="lines+markers",
                line={"color": color("confirmed"), "width": 2, "dash": "dash"},
                marker={"size": 7, "symbol": "square"},
            )
        )
    figure.add_hline(
        y=threshold,
        line_dash="dot",
        line_color=color("ink-muted"),
        annotation_text=f"threshold {threshold:.2f}",
        annotation_position="bottom left",
        annotation_font={"color": color("ink-muted"), "size": 11},
    )
    figure.update_layout(
        **plotly_layout(
            height=height,
            yaxis={"range": [0, 1.05], "title": {"text": "probability"}},
            xaxis={"title": {"text": "windows ahead"}},
        )
    )
    st.plotly_chart(figure, use_container_width=True)


def risk_over_time(
    stamps: Sequence[datetime],
    observed: Sequence[float],
    *,
    threshold: float,
    split_index: int,
    height: int = 300,
) -> None:
    """Observed risk through the observed window, flat beyond the cut.

    The region after the cut is drawn in the "insufficient" colour because those
    windows have not happened yet.
    """
    figure = go.Figure()
    figure.add_trace(
        go.Scatter(
            x=list(stamps[:split_index]),
            y=list(observed[:split_index]),
            name="Observed",
            mode="lines",
            line={"color": color("accent"), "width": 2},
        )
    )
    if split_index < len(stamps):
        future = list(stamps[split_index - 1 :])
        figure.add_trace(
            go.Scatter(
                x=future,
                y=[observed[split_index - 1]] * len(future),
                name="Not yet observed",
                mode="lines",
                line={"color": color("insufficient"), "width": 1, "dash": "dot"},
            )
        )
    figure.add_hline(y=threshold, line_dash="dot", line_color=color("risk-concerning"))
    figure.update_layout(
        **plotly_layout(height=height, yaxis={"range": [0, 1.05], "title": {"text": "risk"}})
    )
    st.plotly_chart(figure, use_container_width=True)


def grouped_bars(
    categories: Sequence[str],
    series: dict[str, Sequence[float]],
    *,
    height: int = 280,
    y_title: str = "",
    value_format: str = "{:.3f}",
) -> None:
    """Grouped comparison bars. Used for every model-vs-model table."""
    figure = go.Figure()
    palette = [
        color("risk-elevated"),
        color("risk-concerning"),
        color("risk-critical"),
        color("insufficient"),
    ]
    for index, (name, values) in enumerate(series.items()):
        figure.add_trace(
            go.Bar(
                x=list(categories),
                y=list(values),
                name=name,
                marker_color=palette[index % len(palette)],
                text=[value_format.format(v) for v in values],
                textposition="outside",
                textfont={"color": color("ink-secondary"), "size": 10},
            )
        )
    figure.update_layout(
        **plotly_layout(height=height, barmode="group", yaxis={"title": {"text": y_title}})
    )
    st.plotly_chart(figure, use_container_width=True)


def sparkline(
    values: Sequence[float],
    *,
    probability: bool = False,
    height: int = 44,
) -> None:
    """Inline trend. Compact enough to sit inside a table cell."""
    if not values:
        return
    line = risk_color(values[-1]) if probability else color("accent")
    figure = go.Figure(
        go.Scatter(
            x=list(range(len(values))),
            y=list(values),
            mode="lines",
            line={"color": line, "width": 1.5},
            hoverinfo="skip",
            showlegend=False,
        )
    )
    figure.update_layout(
        **plotly_layout(
            height=height,
            margin={"l": 0, "r": 0, "t": 0, "b": 0},
            xaxis={"visible": False, "fixedrange": True},
            yaxis={"visible": False, "fixedrange": True},
        )
    )
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})


__all__ = [
    "Stat",
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
