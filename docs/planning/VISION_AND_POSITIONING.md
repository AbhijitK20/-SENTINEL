# Vision And Positioning

## Product Vision

Trajectory is a predictive cyber-defence layer that learns the direction of network behaviour and warns defenders about likely next attack stages before the progression is complete.

## Problem With Static Detection

Flow-by-flow classification loses the order, timing, and relationships between events. Reconnaissance, authentication anomalies, internal access, and command-and-control indicators can be weak individually but meaningful as a trajectory.

## Positioning

> Existing security tools describe what happened. Trajectory estimates what is likely to happen next, identifies potentially affected assets, and shows the evidence supporting that forecast.

## Differentiators

- Forecast trajectory instead of only current classification
- Joint use of flow-level and packet-level-derived evidence
- K-step future-state rollout
- Attack-stage and affected-asset context
- Human-readable evidence for every forecast
- Offline-first and reproducible
- Explicit comparison against a static logistic-regression baseline

## One-Minute Explanation

Trajectory converts network telemetry into a sequence of network states. A temporal model learns how those states evolve and simulates several future windows. The analyst sees the probability of infiltration, likely next attack stage, likely affected assets, and the traffic evidence behind the forecast.

## Product Principles

1. Forecasts are probabilities, not certainty.
2. Evidence is shown with every prediction.
3. Unknown or insufficient evidence is a valid output.
4. No automated blocking is performed by the prototype.
5. Claims must be supported by reproducible evaluation.
