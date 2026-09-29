# Design System — SENTINEL

## Stack
- framework: Streamlit 1.4x (script mode), plain Python — no component framework
- styling: one generated stylesheet of CSS custom properties (`frontend/theme.py`)
- components: hand-built HTML renderers (`frontend/components.py`), no UI library
- charts: Plotly, every layout from `tokens.plotly_layout()`
- icons: text glyphs and inline CSS shapes — no icon library
- motion: CSS transitions only, one `prefers-reduced-motion` guard
- theme file: `.streamlit/config.toml`, generated from the tokens

The previous version of this file described a Next.js + Tailwind + Radix stack
that does not exist in this repository. It is rewritten to describe the code
that is actually here, so it can be enforced rather than aspirational.

## Tokens
Single source of truth: `src/sentinel/frontend/tokens.py`. No hex literal may
appear anywhere else in `src/sentinel/dashboard/` or `src/sentinel/frontend/`
(only the generated `:root` block contains them), and
`tests/test_frontend.py::test_no_hex_outside_the_token_module` fails the build
if one does.

- risk ramp (the only bright thing): `#45799F` → `#6FA0B8` → `#C9B458` → `#D98324` → `#CE4343`
- confirmed (observed ground truth, outside the ramp): `#C64B4B`
- insufficient (unmeasured, outside the ramp): `#667590`
- canvas dark: `#0E1116` / `#161A21` / `#1E242D` / `#262C36` / `#2D3544` / `#354052`
- canvas light: `#FAFAF8` / `#FFFFFF` / `#F0F1EE` / `#E8E9E6` / `#DDDEDB` / `#D2D3D0`,
  token names prefixed `light-` so the flattened palette cannot collide
- ink: `#E6E9EE` / `#A0AAB8` / `#8194AB` / `#4A5568`
- accent: `#6FA0B8` (matches risk-elevated — restrained)
- spacing: 4px base; radius: 4px / 8px only; borders over shadows on dark

Every ink and every ramp step clears WCAG AA on every surface it is used on
(body ink ≥ 4.5:1, UI marks ≥ 3:1). The values above were solved for that
requirement after the first pass failed it; `tests/test_frontend.py` asserts the
ratios so they cannot silently regress.

## Design direction

The subject is **time and probability**: a defender watching a network at 3 a.m.
who has to decide within seconds whether something is happening.

**Time is the spine.** Every screen that shows a trajectory renders the same
time axis in the same place, and every screen states the window it is looking at
(`ui.time_spine`, the "Observed through …" line on Forecast).

**Only probability is bright.** Chrome is neutral; colour is a measurement,
reserved for the risk ramp. A quiet screen is nearly monochrome, and when
something is wrong the colour means something specific.

**Observed and forecast are never confusable.** `confirmed` sits outside the
risk ramp, every probability surface carries the observed/forecast legend
(`ui.observed_forecast_legend`), and a simulation always says in words that it
is simulated.

**Insufficient is not low risk.** A missing measurement renders as
`ui.insufficient`, hatched and grey — deliberately not a ramp colour.

**Every number names its method.** Screens carry a `ui.method_note` stating what
produced the value ("standardized value × fitted coefficient", "one-step
least-squares norm 2.7e5"). A number without a method is not actionable.

## Decisions
- 2026-09-17 — init: Next.js + Tailwind + Radix (did not match the repository).
- 2026-09-26 — rewritten for the real stack: Streamlit + generated CSS + Plotly.
  Design direction and token names kept; the stack description was fiction.
- 2026-09-26 — screen bodies extracted to `dashboard/screens.py`; `app.py` is now
  a shell that owns only theme, data/model lifecycle, and routing. A 1400-line
  script could not be restyled without a rewrite, and a rewrite without
  extraction would have to be repeated.
- 2026-09-26 — light canvas tokens renamed `light-*`. Dark and light had shared
  names, so `get_all_colors()` silently returned light values while the CSS was
  dark — a palette that disagreed with itself.
- 2026-09-26 — contrast solved, not eyeballed: `risk-quiet`, `risk-severe`,
  `confirmed`, `insufficient` and `ink-muted` were lightened until each clears AA
  on the surface it is used on. Hue and ramp ordering are unchanged.
- 2026-09-26 — `network_graphs.py` and both tab modules moved onto tokens; they
  carried a pre-token Tailwind palette and `#0b0d12` plot backgrounds.
- 2026-09-26 — the world-model tab's two hand-rolled charts were deleted in favour
  of `ui.probability_timeline` and `ui.grouped_bars`, so a chart cannot exist
  outside the design system.
- 2026-09-27 — motion layer added. Every animation answers one of four
  questions: a value arrived, a state changed, attention is needed, or a surface
  is being acted on. Nothing animates decoratively.
- 2026-09-27 — stat tiles detect a changed value across renders and react once,
  via a small session-state store. A streaming surface that re-renders every two
  seconds would be unreadable if every redraw animated.
- 2026-09-27 — one `prefers-reduced-motion: reduce` block disables all of it,
  including the ambient wash, the banner sheen, and the meter fill origin.

## Components (`src/sentinel/frontend/components.py`)

| Component | Purpose | States |
|---|---|---|
| `header` | identity + dataset identity | — |
| `lede` | one-paragraph orientation | — |
| `panel` / `end_panel` | titled surface | — |
| `method_note` | how a number was produced | — |
| `stats` | responsive stat grid | empty → `empty()` |
| `risk_meter` | probability, band label, uncertainty band, threshold | spread-aware |
| `ramp` | risk-ramp legend | — |
| `stage_badge` | stage + confidence word + MITRE reference | — |
| `banner` | degraded / error / info / insufficient | 4 tones |
| `degraded` | honest "running without X" | — |
| `insufficient` | unmeasured ≠ low risk | — |
| `evidence` | feature evidence with direction | empty → `empty()` |
| `time_spine` | the shared observed/forecast axis | — |
| `observed_forecast_legend` | persistent measured-vs-simulated strip | — |
| `empty` | icon + heading + explanation | — |
| `skeleton` | loading placeholder matching real geometry | — |
| `live_value` | a value still updating, flashed once when it changes | change-reactive |
| `probability_timeline` | forecast curve, threshold, realised overlay | Plotly transitions |
| `risk_over_time` | observed risk with an unobserved tail | Plotly transitions |
| `grouped_bars` | model-vs-model comparison | Plotly transitions |
| `sparkline` | inline trend for a table cell | static (cell-sized) |
| `.sntl-action` | interactive surface: hover, active, focus-visible, disabled | all four |

## Motion

Motion is a system, not a pile of keyframes. Four questions earn an animation:

1. **A value arrived** — stat tiles rise in sequence, the risk meter fill grows
   from zero, the numeral pops, evidence rows cascade.
2. **A state changed** — a stat tile whose value moved flashes once; the live
   dot appears on a streaming surface. Change is detected against the previous
   render (session state), so a value that does not move does not animate.
3. **Attention is needed** — a live stage badge breathes (faster at severe), the
   threshold marker breathes, a warning banner carries a slow travelling sheen,
   attack ticks on the time spine pulse. All of these are paired with a text
   label, so the motion reinforces meaning rather than carrying it.
4. **A surface is acted on** — tiles and panels lift on hover and press on
   active, the header mark has a 7-second sheen, the ambient wash drifts behind
   the canvas at ≤10% opacity.

Everything else is deliberately still. A dense analyst surface that moves
constantly is unreadable, so infinite loops are limited to the attention and
ambient cases above, and durations come from the motion tokens (100/150/200/300/
400 ms) rather than being invented per component.

`prefers-reduced-motion: reduce` stops all of it — entrances, loops, the
ambient wash, the banner sheen, and the meter fill origin.

## Screens (`src/sentinel/dashboard/screens.py`)

Overview (split composition) · Forecast (walk-forward cut, stage mapping,
evidence, trust ledger) · World model (imagination + open-loop skill) · Replay
(forecast vs reality) · States (one window in full) · Comparison (baseline vs
temporal) · Live (streaming) · Metrics (weights, split audit, config) · Demo
(guided five-step) · Attack story (educational narrative).

## Non-Goals
- No icon library (text glyphs and CSS shapes only)
- No animation library (CSS transitions only)
- No UI component library (the component set is small enough to own)
- No light theme yet: tokens exist and are tested, but only dark ships
- No Figma sync

## The Next.js console in `web/` was removed on 2026-09-29

There was a `web/apps/console/` Next.js + Tailwind + Radix prototype in this
repository. It is gone. The reasons, so the decision is on the record:

- **Nothing referenced it.** Not `docker-compose.yml`, not any Dockerfile, not
  the Makefile, not CI, not a single test. It was not part of the application.
- **It could not build.** `next.config.js` sets
  `transpilePackages: ["@sentinel/tokens", "@sentinel/ui"]` and rewrites them to
  `packages/*/src`; neither directory exists (only `__init__.py` stubs). There
  was no lockfile, no `next-env.d.ts`, no ESLint config.
- **It made no requests.** Every `.tsx` rendered hardcoded fixture values, so it
  displayed numbers that were not measured anywhere.
- **It duplicated the design system with a drifted palette.** `web/apps/console/src/styles/globals.css`
  still carried the pre-contrast-fix colours, which fail the WCAG AA bar that
  `tests/test_frontend.py` enforces on the Python tokens.
- **Its one commit was unrelated** — a lint fix to a Python test.

A half-built second frontend is worse than none in a submission: it invites the
question "which one is the product?" and it cannot be shown to work. The
dashboard in `src/sentinel/dashboard/` is the application, and its design system
is enforced as executable invariants by `tests/test_frontend.py`.
