# SPDX-License-Identifier: Apache-2.0
"""Inject the design system into a Streamlit app.

One stylesheet, generated from :mod:`sentinel.frontend.tokens`, replaces the
ad-hoc inline styling the app used before. It carries:

- every token as a CSS custom property (the only place hex values live),
- the four interactive states for every custom element, so a clickable card
  looks and behaves like a control,
- a ``prefers-reduced-motion`` guard around every transition,
- a persistent "observed vs forecast" legend strip, because conflating them is
  the one mistake this product must never make.

Call :func:`apply_theme` once, before any other Streamlit call.
"""

from __future__ import annotations

import html

import streamlit as st

from sentinel.frontend.tokens import (
    RADIUS,
    RISK_RAMP,
    css_variables,
    streamlit_theme,
)

_STYLESHEET_MARKER = "/* sentinel-design-system */"


def _variable_block() -> str:
    return "\n".join(f"  {name}: {value};" for name, value in sorted(css_variables().items()))


def _base_css() -> str:
    """Layout and typography. Colour is always a var(), never a literal."""
    return f"""
{_STYLESHEET_MARKER}
:root {{
{_variable_block()}
}}

/* ── Shell ─────────────────────────────────────────────────────────── */
.block-container {{
  padding: var(--space-6) var(--space-8) var(--space-16);
  max-width: 1600px;
}}

/* ── App header ────────────────────────────────────────────────────── */
.sntl-header {{
  display: flex;
  align-items: baseline;
  gap: var(--space-4);
  padding: var(--space-2) 0 var(--space-4);
  border-bottom: 1px solid var(--hairline);
  margin-bottom: var(--space-6);
}}
.sntl-header__mark {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-section-size);
  font-weight: 700;
  letter-spacing: 0.14em;
  color: var(--ink);
}}
.sntl-header__sub {{
  font-size: var(--type-label-size);
  color: var(--ink-muted);
  letter-spacing: var(--type-label-tracking);
  text-transform: uppercase;
}}
.sntl-header__spacer {{ flex: 1 1 auto; }}
.sntl-header__meta {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-micro-size);
  color: var(--ink-muted);
}}

/* ── Panels ────────────────────────────────────────────────────────── */
/* The panel box itself is a native `st.container(border=True)`, so its border,
   background and radius come from the app's own chrome rather than from a
   hand-rolled div - see `components.panel`. Only the text inside it is ours. */
.sntl-panel__title {{
  font-size: var(--type-section-size);
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ink);
  margin: 0 0 var(--space-1) 0;
}}
.sntl-panel__hint {{
  font-size: var(--type-label-size);
  color: var(--ink-muted);
  margin: 0 0 var(--space-3) 0;
}}

/* ── Stat tile ─────────────────────────────────────────────────────── */
.sntl-stats {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: var(--space-3);
  margin-bottom: var(--space-4);
}}
.sntl-stat {{
  background: var(--bg-panel);
  border: 1px solid var(--hairline);
  border-left: 2px solid var(--accent);
  border-radius: var(--radius-sm);
  padding: var(--space-3) var(--space-4);
  min-width: 0;
}}
.sntl-stat__label {{
  font-size: var(--type-micro-size);
  letter-spacing: var(--type-micro-tracking);
  text-transform: uppercase;
  color: var(--ink-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.sntl-stat__value {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-section-size);
  line-height: var(--type-section-line);
  color: var(--ink);
  margin-top: var(--space-1);
  word-break: break-word;
}}
.sntl-stat__note {{
  font-size: var(--type-micro-size);
  color: var(--ink-muted);
  margin-top: var(--space-1);
}}
.sntl-stat--quiet {{ border-left-color: var(--risk-quiet); }}
.sntl-stat--elevated {{ border-left-color: var(--risk-elevated); }}
.sntl-stat--concerning {{ border-left-color: var(--risk-concerning); }}
.sntl-stat--critical {{ border-left-color: var(--risk-critical); }}
.sntl-stat--severe {{ border-left-color: var(--risk-severe); }}
.sntl-stat--neutral {{ border-left-color: var(--hairline-strong); }}

/* ── Risk meter ────────────────────────────────────────────────────── */
.sntl-meter {{
  background: var(--bg-canvas);
  border: 1px solid var(--hairline);
  border-radius: var(--radius-sm);
  padding: var(--space-4);
  margin-bottom: var(--space-4);
}}
.sntl-meter__head {{
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--space-3);
  margin-bottom: var(--space-3);
}}
.sntl-meter__label {{
  font-size: var(--type-label-size);
  text-transform: uppercase;
  letter-spacing: var(--type-label-tracking);
  color: var(--ink-muted);
}}
.sntl-meter__value {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-display-size);
  line-height: var(--type-display-line);
  font-weight: 700;
  letter-spacing: var(--type-display-tracking);
}}
.sntl-meter__track {{
  position: relative;
  height: 8px;
  background: var(--bg-base);
  border: 1px solid var(--hairline);
  border-radius: 2px;
  overflow: hidden;
}}
.sntl-meter__fill {{ position: absolute; inset: 0 auto 0 0; }}
.sntl-meter__band {{
  position: absolute;
  top: 0;
  bottom: 0;
  border-left: 1px solid var(--bg-base);
  opacity: 0.55;
}}
.sntl-meter__threshold {{
  position: absolute;
  top: -3px;
  bottom: -3px;
  width: 2px;
  background: var(--ink-secondary);
}}
.sntl-meter__foot {{
  display: flex;
  justify-content: space-between;
  gap: var(--space-3);
  margin-top: var(--space-2);
  font-size: var(--type-micro-size);
  color: var(--ink-muted);
}}
.sntl-meter__band-label {{
  text-transform: uppercase;
  letter-spacing: var(--type-micro-tracking);
  font-weight: 500;
}}

/* ── Stage badge ───────────────────────────────────────────────────── */
.sntl-stage {{
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  border: 1px solid var(--hairline-strong);
  background: var(--bg-raised);
  border-radius: 999px;
  padding: var(--space-1) var(--space-3);
  font-size: var(--type-label-size);
  color: var(--ink);
  line-height: var(--type-label-line);
}}
.sntl-stage__dot {{
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  flex: 0 0 auto;
}}
.sntl-stage__conf {{
  color: var(--ink-muted);
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-micro-size);
}}
.sntl-stage--mitre {{
  border-color: var(--confirmed);
  background: transparent;
}}

/* ── Observed vs forecast strip ────────────────────────────────────── */
.sntl-legend {{
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-4);
  border: 1px solid var(--hairline);
  border-radius: var(--radius-sm);
  background: var(--bg-canvas);
  padding: var(--space-2) var(--space-4);
  margin-bottom: var(--space-4);
  font-size: var(--type-label-size);
  color: var(--ink-secondary);
}}
.sntl-legend__item {{ display: inline-flex; align-items: center; gap: var(--space-2); }}
.sntl-legend__swatch {{
  width: 10px;
  height: 10px;
  border-radius: 2px;
  flex: 0 0 auto;
}}
.sntl-legend__swatch--observed {{
  background: var(--confirmed);
  border: 1px solid var(--ink-secondary);
}}
.sntl-legend__swatch--forecast {{
  background: var(--accent-subtle);
  border: 1px solid var(--accent);
}}
.sntl-legend__note {{ color: var(--ink-muted); margin-left: auto; }}

/* ── Banner (degraded / error / caveat) ────────────────────────────── */
.sntl-banner {{
  display: flex;
  gap: var(--space-3);
  align-items: flex-start;
  border: 1px solid var(--hairline-strong);
  border-left-width: 3px;
  border-radius: var(--radius-sm);
  background: var(--bg-panel);
  padding: var(--space-3) var(--space-4);
  margin-bottom: var(--space-3);
}}
.sntl-banner--degraded {{ border-left-color: var(--risk-concerning); }}
.sntl-banner--error {{ border-left-color: var(--risk-severe); }}
.sntl-banner--info {{ border-left-color: var(--accent); }}
.sntl-banner--insufficient {{ border-left-color: var(--insufficient); }}
.sntl-banner__icon {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-label-size);
  color: var(--ink-muted);
  flex: 0 0 auto;
  padding-top: 1px;
}}
.sntl-banner__title {{
  font-size: var(--type-body-size);
  font-weight: 600;
  color: var(--ink);
  margin: 0 0 var(--space-1) 0;
}}
.sntl-banner__body {{
  font-size: var(--type-label-size);
  color: var(--ink-secondary);
  margin: 0;
}}

/* ── Evidence list ─────────────────────────────────────────────────── */
.sntl-evidence {{ display: flex; flex-direction: column; gap: var(--space-1); }}
.sntl-evidence__item {{
  display: grid;
  grid-template-columns: 1fr auto;
  gap: var(--space-3);
  align-items: baseline;
  border-bottom: 1px solid var(--hairline);
  padding: var(--space-2) 0;
  font-size: var(--type-body-size);
  color: var(--ink-secondary);
}}
.sntl-evidence__item:last-child {{ border-bottom: none; }}
.sntl-evidence__value {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-data-size);
  color: var(--ink);
  white-space: nowrap;
}}
.sntl-evidence__dir {{
  font-size: var(--type-micro-size);
  text-transform: uppercase;
  letter-spacing: var(--type-micro-tracking);
  color: var(--ink-muted);
}}
.sntl-evidence__dir--up {{ color: var(--risk-critical); }}
.sntl-evidence__dir--down {{ color: var(--risk-quiet); }}

/* ── Time spine ────────────────────────────────────────────────────── */
.sntl-spine {{
  display: flex;
  align-items: center;
  gap: var(--space-3);
  border: 1px solid var(--hairline);
  border-radius: var(--radius-sm);
  background: var(--bg-canvas);
  padding: var(--space-2) var(--space-3);
  margin-bottom: var(--space-4);
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-data-size);
  color: var(--ink-secondary);
  overflow-x: auto;
}}
.sntl-spine__tick {{
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-1);
  flex: 0 0 auto;
  min-width: 54px;
}}
.sntl-spine__tick-label {{
  font-size: var(--type-micro-size);
  color: var(--ink-muted);
}}
.sntl-spine__tick--observed .sntl-spine__tick-label {{ color: var(--ink-secondary); }}
.sntl-spine__tick--forecast .sntl-spine__tick-label {{ color: var(--accent); }}
.sntl-spine__bar {{
  width: 100%;
  height: 4px;
  border-radius: 2px;
  background: var(--hairline);
}}
.sntl-spine__tick--attack .sntl-spine__bar {{ background: var(--confirmed); }}

/* ── Empty / loading states ────────────────────────────────────────── */
.sntl-empty {{
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-2);
  text-align: center;
  border: 1px dashed var(--hairline-strong);
  border-radius: var(--radius-lg);
  padding: var(--space-10) var(--space-6);
  color: var(--ink-muted);
}}
.sntl-empty__icon {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-section-size);
  color: var(--hairline-strong);
}}
.sntl-empty__title {{
  font-size: var(--type-body-size);
  font-weight: 600;
  color: var(--ink-secondary);
  margin: 0;
}}
.sntl-empty__body {{
  font-size: var(--type-label-size);
  color: var(--ink-muted);
  margin: 0;
  max-width: 46ch;
}}
.sntl-skeleton {{
  background: var(--bg-panel);
  border: 1px solid var(--hairline);
  border-radius: var(--radius-sm);
  height: 88px;
  margin-bottom: var(--space-3);
  background-image: linear-gradient(
    90deg,
    var(--bg-panel) 0%,
    var(--bg-raised) 50%,
    var(--bg-panel) 100%
  );
  background-size: 200% 100%;
  animation: sntl-shimmer 1.4s linear infinite;
}}
@keyframes sntl-shimmer {{
  from {{ background-position: 200% 0; }}
  to {{ background-position: -200% 0; }}
}}

/* ── Interactive element: all four states ──────────────────────────── */
.sntl-action {{
  display: block;
  width: 100%;
  text-align: left;
  background: var(--bg-panel);
  border: 1px solid var(--hairline);
  border-radius: var(--radius-lg);
  padding: var(--space-3) var(--space-4);
  color: var(--ink);
  font-family: inherit;
  font-size: var(--type-body-size);
  cursor: pointer;
  transition: background var(--motion-duration-fast) var(--motion-easing-out),
              border-color var(--motion-duration-fast) var(--motion-easing-out),
              transform var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-action:hover {{
  background: var(--bg-hover);
  border-color: var(--hairline-strong);
}}
.sntl-action:active {{
  background: var(--bg-active);
  transform: translateY(1px);
}}
.sntl-action:focus-visible {{
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
}}
.sntl-action[aria-disabled="true"],
.sntl-action:disabled {{
  opacity: 0.5;
  cursor: not-allowed;
  pointer-events: none;
}}

/* ── Narrative text ────────────────────────────────────────────────── */
.sntl-lede {{
  font-size: var(--type-body-size);
  line-height: var(--type-body-line);
  color: var(--ink-secondary);
  max-width: 82ch;
  margin: 0 0 var(--space-4) 0;
}}
.sntl-method {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  font-size: var(--type-micro-size);
  color: var(--ink-muted);
  margin: var(--space-2) 0 0 0;
}}
.sntl-ramp {{
  display: flex;
  gap: 2px;
  margin: var(--space-2) 0 0 0;
}}
.sntl-ramp__step {{ height: 4px; flex: 1 1 0; border-radius: 1px; }}

/* ── Streamlit chrome overrides ───────────────────────────────────── */
.stButton > button {{
  background: var(--bg-raised);
  color: var(--ink);
  border: 1px solid var(--hairline-strong);
  border-radius: var(--radius-sm);
  font-size: var(--type-body-size);
  height: var(--density-button-height);
  transition: background var(--motion-duration-fast) var(--motion-easing-out),
              border-color var(--motion-duration-fast) var(--motion-easing-out);
}}
.stButton > button:hover {{
  background: var(--bg-hover);
  border-color: var(--accent);
  color: var(--ink);
}}
.stButton > button:active {{ background: var(--bg-active); }}
.stButton > button:focus-visible {{
  outline: 2px solid var(--focus-ring);
  outline-offset: 2px;
  border-color: var(--accent);
}}
.stButton > button[kind="primary"] {{
  background: var(--accent-active);
  border-color: var(--accent);
  color: var(--ink);
}}
.stButton > button[kind="primary"]:hover {{ background: var(--accent); }}

[data-testid="stSidebar"] {{
  background: var(--bg-canvas);
  border-right: 1px solid var(--hairline);
}}
[data-testid="stMetricValue"] {{
  font-family: "JetBrains Mono", "Cascadia Mono", ui-monospace, monospace;
  color: var(--ink);
}}
[data-testid="stMetricLabel"] {{
  font-size: var(--type-micro-size);
  text-transform: uppercase;
  letter-spacing: var(--type-micro-tracking);
  color: var(--ink-muted);
}}
[data-testid="stCaptionContainer"] p {{ color: var(--ink-muted); }}
h1, h2, h3 {{ letter-spacing: -0.01em; color: var(--ink); }}
hr {{ border-color: var(--hairline); }}

/* ── Motion ──────────────────────────────────────────────────────────
   Every animation answers something: a value arrived, a state changed,
   attention is needed, or a surface is being acted on. Durations come from
   the motion tokens; nothing below invents a timing.
   ────────────────────────────────────────────────────────────────── */

@keyframes sntl-rise {{
  from {{ opacity: 0; transform: translateY(8px); }}
  to   {{ opacity: 1; transform: none; }}
}}
@keyframes sntl-rise-sm {{
  from {{ opacity: 0; transform: translateY(4px); }}
  to   {{ opacity: 1; transform: none; }}
}}
@keyframes sntl-fade {{
  from {{ opacity: 0; }}
  to   {{ opacity: 1; }}
}}
@keyframes sntl-slide-left {{
  from {{ opacity: 0; transform: translateX(-10px); }}
  to   {{ opacity: 1; transform: none; }}
}}
@keyframes sntl-pop {{
  0%   {{ opacity: 0; transform: scale(0.92); }}
  70%  {{ opacity: 1; transform: scale(1.015); }}
  100% {{ opacity: 1; transform: scale(1); }}
}}
/* Grow from the left: used by meter fills and the sidebar indicator. */
@keyframes sntl-grow-x {{
  from {{ transform: scaleX(0); }}
  to   {{ transform: scaleX(1); }}
}}
/* Breathe: attention without a strobe. */
@keyframes sntl-breathe {{
  0%, 100% {{ opacity: 0.55; }}
  50%      {{ opacity: 1; }}
}}
@keyframes sntl-pulse-ring {{
  0%   {{ box-shadow: 0 0 0 0 rgb(255 255 255 / 0.32); }}
  70%  {{ box-shadow: 0 0 0 7px rgb(255 255 255 / 0); }}
  100% {{ box-shadow: 0 0 0 0 rgb(255 255 255 / 0); }}
}}
@keyframes sntl-sheen {{
  0%   {{ transform: translateX(-120%); }}
  60%, 100% {{ transform: translateX(240%); }}
}}
@keyframes sntl-sheen-mark {{
  0%   {{ background-position: 0% 50%; }}
  100% {{ background-position: 200% 50%; }}
}}
@keyframes sntl-flash {{
  0%   {{ background: var(--accent-subtle); }}
  100% {{ background: transparent; }}
}}
@keyframes sntl-float {{
  0%, 100% {{ transform: translateY(0); }}
  50%      {{ transform: translateY(-4px); }}
}}
@keyframes sntl-spine-draw {{
  from {{ transform: scaleX(0); }}
  to   {{ transform: scaleX(1); }}
}}
@keyframes sntl-ambient {{
  0%, 100% {{ opacity: 0.05; transform: translate3d(0, 0, 0) scale(1); }}
  50%      {{ opacity: 0.10; transform: translate3d(0, -14px, 0) scale(1.06); }}
}}

/* Entrance, with a per-element stagger so a group arrives in sequence. */
.sntl-anim-rise {{
  animation: sntl-rise var(--motion-duration-slow) var(--motion-easing-out) both;
  animation-delay: calc(var(--stagger, 0) * 40ms);
}}
.sntl-anim-rise-sm {{
  animation: sntl-rise-sm var(--motion-duration-normal) var(--motion-easing-out) both;
  animation-delay: calc(var(--stagger, 0) * 40ms);
}}
.sntl-anim-fade {{
  animation: sntl-fade var(--motion-duration-normal) var(--motion-easing-out) both;
}}
.sntl-anim-slide-left {{
  animation: sntl-slide-left var(--motion-duration-normal) var(--motion-easing-out) both;
}}
.sntl-anim-pop {{
  animation: sntl-pop var(--motion-duration-slow) var(--motion-easing-spring) both;
}}

/* Stat tile: lifts on hover, rail brightens, number keeps its column width. */
.sntl-stat {{
  transition:
    transform var(--motion-duration-fast) var(--motion-easing-out),
    border-color var(--motion-duration-fast) var(--motion-easing-out),
    background var(--motion-duration-fast) var(--motion-easing-out),
    box-shadow var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-stat:hover {{
  transform: translateY(-2px);
  background: var(--bg-hover);
  border-color: var(--hairline-strong);
  box-shadow: 0 6px 18px -8px rgb(0 0 0 / 0.65);
}}
.sntl-stat:active {{ transform: translateY(0); }}
.sntl-stat__value {{
  font-variant-numeric: tabular-nums;
  transition: color var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-stat--changed .sntl-stat__value {{
  animation: sntl-pop var(--motion-duration-slow) var(--motion-easing-out) both;
}}
.sntl-stat--severe.sntl-stat--changed .sntl-stat__value {{
  animation: sntl-pop var(--motion-duration-slow) var(--motion-easing-out) both,
             sntl-flash 900ms var(--motion-easing-out) 2;
}}

/* Risk meter: the bar grows from zero, so a probability arrives as a quantity. */
.sntl-meter__fill {{
  transform-origin: left center;
  animation: sntl-grow-x var(--motion-duration-page) var(--motion-easing-out) both;
  transition: filter var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-meter:hover .sntl-meter__fill {{ filter: brightness(1.2); }}
.sntl-meter__threshold {{
  animation: sntl-breathe 2.4s var(--motion-easing-in-out) infinite;
}}
.sntl-meter__band {{
  animation: sntl-breathe 3.2s var(--motion-easing-in-out) infinite;
  animation-delay: calc(var(--stagger, 0) * 200ms);
}}
.sntl-meter__value {{
  animation: sntl-pop var(--motion-duration-slow) var(--motion-easing-out) both;
}}

/* Attention: an active finding breathes. The label is always present, so the
   animation reinforces meaning rather than carrying it. */
.sntl-stage--live .sntl-stage__dot {{
  animation: sntl-pulse-ring 2s var(--motion-easing-out) infinite;
}}
.sntl-stage--severe .sntl-stage__dot {{ animation-duration: 1.1s; }}

/* A value that just changed on a streaming surface. */
.sntl-live-value {{
  border-radius: var(--radius-sm);
  padding: 0 var(--space-1);
  animation: sntl-flash var(--motion-duration-page) var(--motion-easing-out) both;
}}
.sntl-live-dot {{
  display: inline-block;
  width: 6px;
  height: 6px;
  margin-right: var(--space-2);
  border-radius: 50%;
  background: var(--risk-elevated);
  animation: sntl-pulse-ring 1.8s var(--motion-easing-out) infinite;
}}

/* Banner: slides in; a warning keeps a slow travelling sheen. */
.sntl-banner {{
  position: relative;
  overflow: hidden;
  animation: sntl-rise-sm var(--motion-duration-normal) var(--motion-easing-out) both;
  transition: border-color var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-banner::after {{
  content: "";
  position: absolute;
  inset: 0;
  width: 36%;
  background: linear-gradient(90deg, transparent, rgb(255 255 255 / 0.07), transparent);
  opacity: 0;
  pointer-events: none;
}}
.sntl-banner--degraded::after,
.sntl-banner--error::after {{
  opacity: 1;
  animation: sntl-sheen 3.6s var(--motion-easing-in-out) infinite;
}}
.sntl-banner--degraded:hover,
.sntl-banner--error:hover {{ border-color: var(--risk-severe); }}
.sntl-banner--info:hover {{ border-color: var(--accent); }}

/* Evidence rows arrive in sequence; hover reveals more of the row. */
.sntl-evidence__item {{
  animation: sntl-rise-sm var(--motion-duration-normal) var(--motion-easing-out) both;
  animation-delay: calc(var(--stagger, 0) * 35ms);
  transition: background var(--motion-duration-fast) var(--motion-easing-out),
              padding-left var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-evidence__item:hover {{ background: var(--bg-hover); padding-left: var(--space-2); }}

/* Time spine: the observed→forecast rule draws itself; the tick under the
   pointer lights up. */
.sntl-spine {{ position: relative; }}
.sntl-spine::before {{
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  height: 1px;
  background: linear-gradient(90deg, var(--confirmed), var(--accent));
  transform-origin: left center;
  animation: sntl-spine-draw var(--motion-duration-page) var(--motion-easing-out) both;
}}
.sntl-spine__bar {{
  transition: background var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-spine__tick:hover .sntl-spine__bar {{ background: var(--accent); }}
.sntl-spine__tick--attack .sntl-spine__bar {{
  animation: sntl-breathe 1.8s var(--motion-easing-in-out) infinite;
}}

/* Interactive surface: lift, press, focus. */
.sntl-action {{
  transition: background var(--motion-duration-fast) var(--motion-easing-out),
              border-color var(--motion-duration-fast) var(--motion-easing-out),
              transform var(--motion-duration-fast) var(--motion-easing-out),
              box-shadow var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-action__title {{
  font-size: var(--type-body-size);
  font-weight: 600;
  color: var(--ink);
  margin-bottom: var(--space-1);
}}
.sntl-action__body {{
  font-size: var(--type-label-size);
  color: var(--ink-secondary);
}}
.sntl-action__cta {{
  display: inline-block;
  margin-top: var(--space-2);
  font-size: var(--type-micro-size);
  text-transform: uppercase;
  letter-spacing: var(--type-micro-tracking);
  color: var(--accent);
  transform: translateX(0);
  transition: transform var(--motion-duration-fast) var(--motion-easing-out);
}}
.sntl-action:hover .sntl-action__cta {{ transform: translateX(4px); }}

/* Small-caps group heading for a block of readouts. */
.sntl-section-label {{
  font-size: var(--type-micro-size);
  text-transform: uppercase;
  letter-spacing: var(--type-micro-tracking);
  color: var(--ink-muted);
  margin: var(--space-4) 0 var(--space-2) 0;
}}

/* Interactive surface: lift on hover, press on active, visible focus. */
.sntl-action:hover {{
  background: var(--bg-hover);
  border-color: var(--accent);
  transform: translateY(-1px);
  box-shadow: 0 8px 20px -10px rgb(0 0 0 / 0.7);
}}
.sntl-action:active {{
  background: var(--bg-active);
  transform: translateY(1px) scale(0.995);
}}

/* Empty state: the glyph drifts, so waiting looks intentional. */
.sntl-empty__icon {{
  animation: sntl-float 3.6s var(--motion-easing-in-out) infinite;
}}

/* Header mark: the one piece of decoration in the product. */
.sntl-header__mark {{
  background: linear-gradient(90deg, var(--ink) 0%, var(--accent) 45%, var(--ink) 90%);
  background-size: 200% 100%;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  animation: sntl-sheen-mark 7s var(--motion-easing-in-out) infinite;
}}

/* Charts fade up on render, so a re-read is a state change, not a jump cut. */
.stPlotlyChart, [data-testid="stPlotlyChart"] {{
  animation: sntl-fade var(--motion-duration-slow) var(--motion-easing-out) both;
}}

/* An ambient wash behind the canvas. Opacity is deliberately tiny: felt, not
   seen. */
body::before {{
  content: "";
  position: fixed;
  inset: -20% -10% auto -10%;
  height: 60vh;
  pointer-events: none;
  z-index: 0;
  background:
    radial-gradient(60% 60% at 18% 0%, var(--accent) 0%, transparent 62%),
    radial-gradient(45% 45% at 82% 8%, var(--risk-critical) 0%, transparent 60%);
  animation: sntl-ambient 18s var(--motion-easing-in-out) infinite;
}}
[data-testid="stAppViewContainer"] > * {{ position: relative; z-index: 1; }}

/* ── Reduced motion: every transition and animation stops ─────────── */
@media (prefers-reduced-motion: reduce) {{
  *, *::before, *::after {{
    animation-duration: 0.001ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.001ms !important;
    scroll-behavior: auto !important;
  }}
  .sntl-skeleton {{ background-image: none; }}
  .sntl-banner::after,
  body::before,
  .sntl-spine::before {{ display: none; }}
  .sntl-meter__fill {{ transform: none; }}
}}

/* ── Responsive: sm (mobile) collapses the grid ───────────────────── */
@media (max-width: 640px) {{
  .block-container {{ padding: var(--space-4) var(--space-4) var(--space-10); }}
  .sntl-header {{ flex-wrap: wrap; gap: var(--space-2); }}
  .sntl-stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .sntl-legend {{ flex-direction: column; align-items: flex-start; gap: var(--space-2); }}
  .sntl-legend__note {{ margin-left: 0; }}
  .sntl-meter__value {{ font-size: var(--type-section-size); }}
}}
"""


_CACHE: dict[str, str] = {}


def stylesheet() -> str:
    """The full stylesheet, generated once per process."""
    if "css" not in _CACHE:
        _CACHE["css"] = _base_css()
    return _CACHE["css"]


def apply_theme(page_title: str = "SENTINEL") -> None:
    """Set the page config and inject the stylesheet. Call exactly once, first."""
    st.set_page_config(
        page_title=page_title,
        page_icon="◈",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(f"<style>{stylesheet()}</style>", unsafe_allow_html=True)


def theme_config_toml() -> str:
    """``[theme]`` block for ``.streamlit/config.toml``, generated from tokens."""
    theme = streamlit_theme()
    lines = ["[theme]"]
    for key, value in theme.items():
        lines.append(f'{key} = "{value}"')
    lines.append(f'baseRadius = "{RADIUS["sm"]}"')
    return "\n".join(lines) + "\n"


def esc(value: object) -> str:
    """Escape a value for interpolation into component HTML."""
    return html.escape(str(value), quote=True)


def ramp_legend() -> str:
    """HTML for the risk ramp used as a legend under probability surfaces."""
    steps = "".join(
        f'<span class="sntl-ramp__step" style="background: {token.value}" '
        f'title="{esc(token.name)} · {esc(token.description)}"></span>'
        for token in RISK_RAMP
    )
    return f'<div class="sntl-ramp">{steps}</div>'


__all__ = [
    "apply_theme",
    "esc",
    "ramp_legend",
    "stylesheet",
    "theme_config_toml",
]
