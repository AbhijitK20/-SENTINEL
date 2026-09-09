# Sprint 7 Plan

## Goal

Deliver the offline analyst interface and deterministic demonstration.

## Outputs

Upload/replay flow, forecast dashboard, comparison view, and report export.

## Status: COMPLETE

Delivered against the Definition of Done:

- Streamlit dashboard (Overview, Forecast with stage-mapping evidence panel,
  Network States, Comparison, Replay walk-forward evaluation, guided two-minute
  Demo tab, Metrics) with observed/forecast labelling on every screen.
- Walk-forward replay evaluation (`trajectory.evaluation`) and Markdown analyst
  report export (`trajectory.report`), downloadable from the UI.
- Deterministic replay: fixed-seed scenario generation; the Demo tab repeats
  identically for a fixed seed.
- Calibrated threshold auto-loads from artifacts; CLI override available.
- One-command reproducibility: `./run_all.sh` runs lint, tests, the full
  benchmark, and regenerates all reports/charts.

## Exit Criteria

A judge can understand the problem, forecast, evidence, and outcome within two minutes — met by the Demo tab's five guided steps with download-able evidence.
