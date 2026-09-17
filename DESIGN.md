# Design System — SENTINEL

## Stack
- framework: Next.js 15 (App Router)
- styling: Tailwind CSS v3 + CSS custom properties
- components: Radix UI primitives + custom domain components
- animation: CSS transitions (no Framer Motion — ponytail: fewer deps)
- icons: inline SVG (no icon library — fewer deps)
- state: TanStack Query (server) + Zustand (UI)

## Tokens
- risk ramp: #3E6C8E → #6FA0B8 → #C9B458 → #D98324 → #B33A3A
- confirmed: #7A2E2E (outside ramp — observed ≠ forecast)
- insufficient: #4A5568 (outside ramp — insufficient ≠ low risk)
- canvas dark: #0E1116 / #161A21 / #1E242D / #262C36
- canvas light: #FAFAF8 / #FFFFFF / #F0F1EE / #E8E9E6
- ink: #E6E9EE / #A0AAB8 / #6B7A8D
- accent: #6FA0B8 (matches risk-elevated — restrained)
- spacing: 4px base, 8px rhythm
- radius: 4px (sm) / 8px (lg) — two values only
- type: Display 28/32, Section 20/28, Body 14/20, Data 13/18 mono, Label 12/16, Micro 11/14
- density: 28px table rows, 32px inputs/buttons

## Design Direction
The subject is **time and probability**. A defender watching a network at 3 a.m.,
needing to decide within seconds whether something is happening.

**The organising idea: time is the spine.**
Every screen has a horizontal time axis in the same position, at the same scale,
synchronised. You scrub time in one place and the whole application moves.

**The colour rule: only probability is allowed to be bright.**
Chrome is neutral. Colour is a measurement, reserved for risk encoding, using one
perceptually-uniform sequential ramp. When everything is quiet, the screen is nearly
monochrome; when something is wrong, the colour is unmistakable and it means something.

## Decisions
- 2026-09-17 — init: Next.js 15 + Tailwind + Radix UI. Dark-first product theme.
- 2026-09-17 — tokens derived from plan §4, not from Tailwind defaults.
- 2026-09-17 — risk ramp is perceptually uniform, colour never sole carrier.
- 2026-09-17 — borders over shadows on dark UI (shadows look muddy).
- 2026-09-17 — two radii only to encode hierarchy.
- 2026-09-17 — mono font only for numeric alignment (tables, hex, IPs).

## Components
- `RiskMeter` — probability with uncertainty band and explicit numeral
- `StageBadge` — MITRE tactic + technique with confidence
- `DegradedBanner` — honest "we are running without X" surface
- `EvidencePanel` — feature values behind a claim, linked to glossary
- `ObservedForecastLegend` — persistent, unmissable distinction
- `FlowTable` — virtualised, keyboard-navigable flow data

## Non-Goals
- No Figma sync
- No image generation
- No icon library (inline SVG only)
- No animation library (CSS transitions only)
