"""Markdown analyst report export for forecasts and replay evaluation.

The report separates observed facts from model forecasts, names its evidence,
and states limitations explicitly. It is generated from contract objects —
nothing is invented at render time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from trajectory.evaluation import ReplayEvaluation
from trajectory.schemas import Forecast

REPORT_VERSION = "report-v1"


def render_report(
    forecast: Forecast,
    *,
    scenario_id: str | None = None,
    evaluation: ReplayEvaluation | None = None,
    dataset_id: str | None = None,
) -> str:
    """Render a forecast (and optional replay evaluation) as a Markdown report."""
    lines: list[str] = [
        "# Trajectory Forecast Report",
        "",
        f"- Generated: {datetime.now(tz=UTC).isoformat()}",
        f"- Forecast model version: `{forecast.model_version}`",
        f"- Report version: `{REPORT_VERSION}`",
    ]
    if scenario_id:
        lines.append(f"- Scenario: `{scenario_id}`")
    if dataset_id:
        lines.append(f"- Dataset: `{dataset_id}`")

    lines += [
        "",
        "## Input Window (observed)",
        "",
        f"- From: {forecast.input_window_start.isoformat()}",
        f"- To: {forecast.input_window_end.isoformat()}",
        "",
        "## Forecast",
        "",
        f"- Horizon: {forecast.horizon_windows} windows",
        f"- Peak infiltration probability: "
        f"**{max(p.infiltration_probability for p in forecast.probability_timeline):.3f}**",
        f"- Predicted stage: **{forecast.predicted_stage.name}** "
        f"(confidence: {forecast.predicted_stage.confidence})",
    ]

    if forecast.lead_time is not None:
        lead = forecast.lead_time
        lead_text = str(lead.lead_windows) if lead.lead_windows is not None else "not crossed"
        lines.append(f"- Forecast lead: {lead_text} windows within horizon {lead.horizon_windows}")

    if forecast.stage_mapping is not None:
        mapping = forecast.stage_mapping
        lines += [
            "",
            "## Stage Mapping (documented rules)",
            "",
            f"- Stage: **{mapping.stage}** · {mapping.mitre_reference or 'no MITRE reference'}",
            f"- Mapping version: `{mapping.mapping_version}`",
            f"- Rationale: {mapping.rationale}",
        ]
        if mapping.evidence:
            lines += [
                "",
                "| Observed evidence | Value | Direction | Confidence |",
                "|---|---:|---|---:|",
            ]
            for ev in mapping.evidence:
                value = f"{ev.observed_value:.1f}" if ev.observed_value is not None else "n/a"
                lines.append(
                    f"| {ev.description} | {value} | {ev.direction} | {ev.confidence:.2f} |"
                )
        else:
            lines += [
                "",
                "_No documented rule fired; evidence is insufficient for a stage hypothesis._",
            ]

    lines += [
        "",
        "## Probability Timeline",
        "",
        "| Window | P(infiltration) | Confidence |",
        "|---|---:|---:|",
    ]
    for point in forecast.probability_timeline:
        lines.append(
            f"| +{point.window} | {point.infiltration_probability:.3f} | {point.confidence:.2f} |"
        )

    if forecast.driving_features:
        lines += [
            "",
            "## Driving Features (model evidence, not causality)",
            "",
            "| Feature | Contribution | Direction |",
            "|---|---:|---|",
        ]
        for feature in forecast.driving_features:
            contribution = f"{feature.contribution:+.3f}"
            lines.append(f"| `{feature.name}` | {contribution} | {feature.direction} |")
        lines.append("")

    if forecast.affected_entities:
        lines += [
            "",
            "## Potentially Affected Entities",
            "",
        ]
        lines += [f"- {entity}" for entity in forecast.affected_entities]

    if forecast.supporting_events:
        lines += [
            "",
            "## Supporting Events (provenance references)",
            "",
        ]
        lines += [f"- `{event}`" for event in forecast.supporting_events]

    if forecast.coverage:
        lines += [
            "",
            "## Coverage",
            "",
            f"- Flow features: {'available' if forecast.coverage.get('flow') else 'unavailable'}",
            (
                "- Packet features: "
                f"{'available' if forecast.coverage.get('packet') else 'unavailable'}"
            ),
        ]

    if forecast.warnings:
        lines += [
            "",
            "## Warnings",
            "",
        ]
        lines += [f"- {warning}" for warning in forecast.warnings]

    if evaluation is not None:
        lines += [
            "",
            "## Replay Evaluation (measured lead time)",
            "",
            f"- Scenarios evaluated: {evaluation.scenarios_evaluated}",
            f"- Decision threshold: {evaluation.decision_threshold:.2f}",
            "- Measured median lead: "
            + (
                f"**{evaluation.measured_median_lead_windows:.1f} windows**"
                if evaluation.measured_median_lead_windows is not None
                else "no creditable lead observed"
            ),
            f"- Forecast crossing rate: {evaluation.forecast_crossing_rate:.2f}",
            f"- False early-warning rate: {evaluation.false_early_warning_rate:.2f}",
            "",
            "### Forecast vs Reality (per scenario)",
            "",
            "| Scenario | Rows | Crossings | Onsets | TP forecasts | False early | Median lead |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for summary in evaluation.summaries:
            lead = (
                f"{summary.median_lead_windows:.1f}"
                if summary.median_lead_windows is not None
                else "n/a"
            )
            lines.append(
                f"| {summary.scenario_id} | {summary.rows} | {summary.threshold_crossings} | "
                f"{summary.realized_onsets} | {summary.true_positive_forecasts} | "
                f"{summary.false_early_warnings} | {lead} |"
            )
        if evaluation.warnings:
            lines += ["", "### Evaluation Warnings", ""]
            lines += [f"- {warning}" for warning in evaluation.warnings]

    lines += [
        "",
        "## Limitations",
        "",
        "- Contributions are standardized feature value × fitted coefficient; "
        "this is model evidence, not causal proof.",
        "- Probabilities are estimates. A positive forecast is decision support, "
        "not authorization for automatic response.",
        "- Results on synthetic replay data validate the pipeline only; they are "
        "not a benchmark claim on real traffic.",
        "",
        f"_{REPORT_VERSION} — every value in this report comes from a typed "
        f"contract; nothing is rendered from free text._",
    ]
    return "\n".join(lines)


def save_report(report: str, output_path: str | Path) -> Path:
    """Write the report to disk and return the path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    return out


__all__ = ["REPORT_VERSION", "render_report", "save_report"]
