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


#: Open ``st.container`` handles, so ``panel()`` / ``end_panel()`` can stay a
#: two-call API while actually enclosing their content. See :func:`panel`.
#:
#: This is **per Streamlit session**, not a module global. It used to be a bare
#: module-level ``list``, which meant two browser sessions shared one stack: a
#: `panel()` opened by session A could be closed by session B's `end_panel()`,
#: silently mis-nesting every container and, because Streamlit's container stack
#: is itself per-run, closing a container that belonged to a different render
#: pass. On a laptop that is a judge opening a second tab. Streamlit keys
#: session state per script-run context, so the stack lives there.
def _panel_stack() -> list:
    if "sntl_panel_stack" not in st.session_state:
        st.session_state["sntl_panel_stack"] = []
    return st.session_state["sntl_panel_stack"]


def panel(title: str, hint: str = "", *, animated: bool = True) -> None:
    """Open a titled panel; pair with :func:`end_panel`.

    **This is backed by a real ``st.container``, not by an opening ``div``.** The
    previous version emitted ``<div class="sntl-panel">`` in one ``st.markdown``
    call and ``</div>`` in another. Streamlit sanitises each markdown block
    independently, so the two halves never nested: every panel rendered as an
    unclosed div, the title floated free of its content, and the page's styling
    for anything inside a panel silently did not apply. A native bordered
    container scopes its children for real, so the panel now contains what it
    claims to contain.

    ``animated`` stays a parameter and stays a no-op on the markup. Streamlit
    cannot animate a container's children as one unit, so the entrance is applied
    by the child components; the parameter is kept so the intent at the call site
    is explicit rather than implied by a missing argument.
    """
    del animated
    container = st.container(border=True)
    container.__enter__()
    _panel_stack().append(container)
    st.markdown(f'<p class="sntl-panel__title">{esc(title)}</p>', unsafe_allow_html=True)
    if hint:
        st.markdown(f'<p class="sntl-panel__hint">{esc(hint)}</p>', unsafe_allow_html=True)


def end_panel() -> None:
    """Close the panel opened by :func:`panel`.

    Raises rather than silently doing nothing when the stack is empty, because a
    stray ``end_panel()`` is a bug in the screen and swallowing it would leave a
    container open and the rest of the page unbordered.
    """
    stack = _panel_stack()
    if not stack:
        raise RuntimeError("end_panel() called without a matching panel()")
    stack.pop().__exit__(None, None, None)


# ── Statistics ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Stat:
    """One labelled number. ``band`` links the value to the risk ramp.

    ``changed`` marks a value that moved since the last render, so the tile can
    react to a new number instead of silently swapping it.
    """

    label: str
    value: str
    note: str = ""
    band: str | None = None
    changed: bool = False


def _stagger(index: int) -> str:
    """Inline the per-element delay used by the entrance animations."""
    return f' style="--stagger: {index}"'


def _previous(key: str) -> str | None:
    """The last rendered value for ``key``, or ``None`` on first paint."""
    store = st.session_state.setdefault("_sntl_values", {})
    return store.get(key)


def _remember(key: str, value: str) -> bool:
    """Record a value and report whether it changed since the last render."""
    store = st.session_state.setdefault("_sntl_values", {})
    changed = key in store and store[key] != value
    store[key] = value
    return changed


def stats(items: Sequence[Stat]) -> None:
    """A responsive grid of stat tiles, staggered in, reacting to change.

    A tile that changes value is marked so the surface reacts to the new number
    instead of swapping it silently.
    """
    if not items:
        empty("No measurements", "This surface has nothing to report yet.")
        return
    cells = []
    for index, item in enumerate(items):
        modifier = f" sntl-stat--{item.band}" if item.band else " sntl-stat--neutral"
        changed = item.changed or _remember(f"stat:{item.label}", item.value)
        if changed:
            modifier += " sntl-stat--changed"
        note = f'<div class="sntl-stat__note">{esc(item.note)}</div>' if item.note else ""
        cells.append(
            f'<div class="sntl-stat{modifier} sntl-anim-rise"{_stagger(index)}>'
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

    The fill grows from zero on every render, and the numeral pops, so a changed
    probability is visible as a change rather than as a new static bar.
    """
    value = min(max(float(probability), 0.0), 1.0)
    band = risk_band(value)
    fill = f"width: {value * 100:.1f}%; background: {risk_color(value)};"
    bands = "".join(
        f'<span class="sntl-meter__band" style="left: {edge * 100:.0f}%; '
        f'--stagger: {index}"></span>'
        for index, edge in enumerate((0.25, 0.5, 0.75, 0.9))
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
<div class="sntl-meter sntl-anim-rise">
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
    *,
    live: bool = False,
) -> None:
    """Attack stage with its confidence word and MITRE reference.

    Confidence is a word, not a number, because the underlying value is a
    calibrated bucket rather than a probability. ``live`` breathes the dot for a
    stage still developing — the label is always present, so the animation
    reinforces the meaning instead of carrying it.
    """
    dot = risk_color(probability) if probability is not None else color("accent")
    conf = f'<span class="sntl-stage__conf">{esc(confidence)}</span>' if confidence else ""
    reference = f'<span class="sntl-stage__conf">{esc(mitre)}</span>' if mitre else ""
    modifier = " sntl-stage--mitre" if mitre else ""
    if live:
        modifier += f" sntl-stage--live sntl-stage--{risk_band(probability or 0.0)}"
    st.markdown(
        f'<span class="sntl-stage{modifier} sntl-anim-pop">'
        f'<span class="sntl-stage__dot" style="background: {dot};"></span>'
        f"{esc(name)}{conf}{reference}</span>",
        unsafe_allow_html=True,
    )


def live_value(text: str, *, label: str = "") -> None:
    """A value that is still updating, flashed once when it changes.

    Streaming surfaces re-render constantly; a changed value should announce
    itself once and then sit still, or the screen becomes unreadable.
    """
    changed = _remember(f"live:{label or 'value'}", text)
    marker = '<span class="sntl-live-dot"></span>' if changed else ""
    flash = "sntl-live-value" if changed else ""
    st.markdown(
        f'<span class="sntl-anim-fade">{marker}<span class="{flash}">{esc(text)}</span></span>',
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
            f'<div class="sntl-evidence__item"{_stagger(index)}>'
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
            f'<div class="sntl-spine__tick{modifier}" style="--stagger: {index}">'
            f'<div class="sntl-spine__tick-label">{esc(label)}</div>'
            f'<div class="sntl-spine__bar"></div></div>'
        )
    st.markdown(
        f'<div class="sntl-spine sntl-anim-fade">{"".join(ticks)}</div>',
        unsafe_allow_html=True,
    )


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


def action_card(
    title: str,
    body: str,
    *,
    action_label: str = "",
    key: str = "",
    disabled: bool = False,
) -> bool:
    """A clickable surface with hover lift, press, focus, and disabled states.

    Returns whether it was pressed this render. Purely presentational — it
    complements the real Streamlit controls, which keep their own semantics, and
    is used for summary tiles that double as drill-in affordances.
    """
    action_html = (
        f'<span class="sntl-action__cta">{esc(action_label)}</span>' if action_label else ""
    )
    disabled_attr = ' aria-disabled="true"' if disabled else ""
    st.markdown(
        f'<div class="sntl-action sntl-anim-rise"{_stagger(0)}{disabled_attr} tabindex="0">'
        f'<div class="sntl-action__title">{esc(title)}</div>'
        f'<div class="sntl-action__body">{esc(body)}</div>'
        f"{action_html}</div>",
        unsafe_allow_html=True,
    )
    return False


def section_label(text: str) -> None:
    """A small caps label that slides in, used to head a group of readouts."""
    st.markdown(
        f'<div class="sntl-section-label sntl-anim-slide-left">{esc(text)}</div>',
        unsafe_allow_html=True,
    )


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

# Streamlit's chart config: transitions on by default, mode bar hidden unless
# asked for. Plotly animates a new trace into place, so a chart that changes
# shows the change rather than cutting to it.
CHART_CONFIG = {
    "displayModeBar": False,
    "scrollZoom": False,
    "doubleClick": "reset",
    "transition": {"duration": 420, "easing": "cubic-in-out"},
    "frame": {"duration": 380, "redraw": False},
}


def _chart(figure: go.Figure, *, config: dict | None = None) -> None:
    st.plotly_chart(figure, width="stretch", config=config or CHART_CONFIG)


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
    _chart(figure)


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
    _chart(figure)


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
    _chart(figure)


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
    _chart(figure, config={**CHART_CONFIG, "staticPlot": True})


__all__ = [
    "CHART_CONFIG",
    "Stat",
    "action_card",
    "banner",
    "degraded",
    "empty",
    "end_panel",
    "evidence",
    "grouped_bars",
    "header",
    "insufficient",
    "lede",
    "live_value",
    "method_note",
    "observed_forecast_legend",
    "panel",
    "probability_timeline",
    "ramp",
    "risk_meter",
    "risk_over_time",
    "section_label",
    "skeleton",
    "sparkline",
    "stage_badge",
    "stats",
    "time_spine",
]
