# Demo Plan

## Objective

Show the complete analyst loop: observe network state, forecast the next stage,
compare forecast with replay reality, correlate an incident, and exercise a
safe containment response while explaining the evidence.

## Two-Minute Sequence

1. 0:00-0:15: State the gap between static detection and trajectory analysis.
2. 0:15-0:35: Train once and show the Overview split/data contract.
3. 0:35-0:55: Move the Forecast walk-forward slider through reconnaissance.
4. 0:55-1:15: Run Replay and show Forecast versus Reality rows.
5. 1:15-1:35: Open Attack Story and advance the topology/packet workflow.
6. 1:35-1:50: Simulate containment and show the before/after defense comparison. This is simulated containment, not a real firewall action.
7. 1:50-2:00: Show Grafana live metrics and explain the honest lead-time limitation.

## Demo Rules

- Use deterministic data.
- Never hide a failed prediction.
- Clearly label prediction versus observation.
- Avoid claiming production readiness.
- Label synthetic, observed, forecast, and simulated-containment states separately.
- Explain that simulated containment is a demo state, not a real firewall action.
- Do not present the Dubsmash-inspired workflow as a verified reconstruction of the historical intrusion path.
