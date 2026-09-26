# SPDX-License-Identifier: Apache-2.0
"""Dashboard screens.

Each screen is a function that takes a :class:`ScreenContext` and renders one
tab. The shell (``dashboard/app.py``) owns data loading and model state; screens
own layout and copy. No screen hardcodes a colour, a radius, or a chart
background — those come from :mod:`sentinel.frontend`.

Every screen states its method: a number without a stated method is a number an
analyst cannot act on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import plotly.graph_objects as go
import streamlit as st

from sentinel.case_studies import dubsmash_inspired_case, packet_flow_steps, replay_topology
from sentinel.dashboard.network_graphs import kill_chain_figure, topology_figure
from sentinel.dashboard.state import LEDGER_PATH
from sentinel.evaluation import evaluate_replay
from sentinel.features import vectorize_states
from sentinel.frontend import ui
from sentinel.frontend.tokens import color, plotly_layout
from sentinel.ledger import AlertLedger
from sentinel.predict import DECISION_THRESHOLD, forecast
from sentinel.report import render_report
from sentinel.schemas import SPLIT_NAMES


@dataclass
class ScreenContext:
    """Everything a screen may read. Screens never mutate the model."""

    labelled: list
    samples: list
    manifest: Any
    baseline_run: Any
    temporal_run: Any
    loaded: Any
    dataset_id: str
    dataset_fingerprint: str
    forecast_horizon: int
    window_seconds: int
    stride_seconds: int
    sequence_length: int

    @property
    def schema(self):
        return self.baseline_run.result.feature_schema

    def states(self, scenario_id: str) -> list:
        return [item.state for item in self.labelled if item.scenario_id == scenario_id]

    def labelled_for(self, scenario_id: str) -> list:
        return [item for item in self.labelled if item.scenario_id == scenario_id]

    def split_of(self) -> dict[str, str]:
        return {
            scenario: split
            for split in SPLIT_NAMES
            for scenario in getattr(self.manifest, f"{split}_scenarios")
        }

    def scenarios(self) -> list[str]:
        return sorted(self.split_of())

    def label_for(self, scenario_id: str, window_start) -> str | None:
        return next(
            (
                item.label.attack_stage
                for item in self.labelled
                if item.scenario_id == scenario_id and item.state.window_start == window_start
            ),
            None,
        )

    def select_scenario(self, key: str, label: str = "Scenario") -> str | None:
        """Scenario picker annotated with its split, so the holdout is visible."""
        mapping = self.split_of()
        if not mapping:
            return None
        chosen = st.selectbox(
            label,
            sorted(mapping),
            format_func=lambda s: f"{s} · {mapping[s]}",
            key=key,
        )
        return chosen


# ── Overview ────────────────────────────────────────────────────────────


def overview(ctx: ScreenContext) -> None:
    """Where the data comes from and how it is divided. No model output."""
    ui.lede(
        "The split is the whole argument. Whole scenarios are assigned to train, "
        "validation, or test before a single window is built, so no window of a "
        "held-out scenario is ever seen during fitting. Everything downstream "
        "inherits that division."
    )

    split_counts = {
        name: sum(
            1 for i in ctx.labelled if i.scenario_id in getattr(ctx.manifest, f"{name}_scenarios")
        )
        for name in SPLIT_NAMES
    }
    positives = {
        name: sum(
            1
            for i in ctx.labelled
            if i.label.infiltration and i.scenario_id in getattr(ctx.manifest, f"{name}_scenarios")
        )
        for name in SPLIT_NAMES
    }

    ui.stats(
        [
            ui.Stat(
                "Scenarios",
                str(
                    len(ctx.manifest.train_scenarios)
                    + len(ctx.manifest.validation_scenarios)
                    + len(ctx.manifest.test_scenarios)
                ),
            ),
            ui.Stat("Windows", f"{len(ctx.labelled):,}"),
            ui.Stat("Sequence samples", f"{len(ctx.samples):,}"),
            ui.Stat("Features / window", str(ctx.schema.width)),
            ui.Stat("Forecast horizon", f"+{ctx.forecast_horizon} win"),
        ]
    )

    ui.panel("Split composition", "Windows and infiltration-positive windows per split.")
    columns = st.columns(2)
    with columns[0]:
        figure = go.Figure(
            go.Bar(
                x=list(split_counts),
                y=[split_counts[name] for name in split_counts],
                marker_color=color("risk-elevated"),
                text=[split_counts[name] for name in split_counts],
                textposition="outside",
            )
        )
        figure.update_layout(**plotly_layout(height=260, yaxis={"title": {"text": "windows"}}))
        st.plotly_chart(figure, width="stretch")
    with columns[1]:
        stage_counts: dict[str, int] = {}
        for item in ctx.labelled:
            stage_counts[item.label.attack_stage] = stage_counts.get(item.label.attack_stage, 0) + 1
        figure = go.Figure(
            go.Pie(
                labels=list(stage_counts),
                values=list(stage_counts.values()),
                hole=0.45,
                marker={
                    "colors": [
                        color("risk-quiet"),
                        color("risk-concerning"),
                        color("risk-critical"),
                    ]
                },
            )
        )
        figure.update_layout(**plotly_layout(height=260))
        st.plotly_chart(figure, width="stretch")
    ui.end_panel()

    ui.stats(
        [
            ui.Stat(f"{name} positives", f"{positives[name]:,}", band="elevated")
            for name in SPLIT_NAMES
        ]
        + [ui.Stat("Telemetry levels", "flow + packet" if ctx.schema.width > 74 else "flow only")]
    )
    ui.method_note(
        f"Windows from {ctx.dataset_id} · {ctx.window_seconds}s windows / "
        f"{ctx.stride_seconds}s stride · seed in dataset fingerprint"
    )


# ── Forecast ────────────────────────────────────────────────────────────


def forecast_screen(ctx: ScreenContext) -> None:
    """Walk-forward forecast: everything below is derived from the cut."""
    ui.observed_forecast_legend("Timeline is a forecast; the realised row is measured.")
    scenario = ctx.select_scenario("forecast_scenario", "Scenario to forecast from")
    if scenario is None:
        ui.empty("No scenarios", "Train on a data source to produce scenarios.")
        return
    states = ctx.states(scenario)
    if not states:
        ui.empty("No windows", f"{scenario} produced no network states.")
        return

    cut = st.slider(
        "Forecast from window",
        min_value=1,
        max_value=len(states),
        value=len(states),
        help="Drag left to replay earlier moments. The forecast, stage, evidence "
        "and lead time are recomputed from that cut — never a static render.",
    )
    observed = states[cut - 1]
    ui.time_spine(
        [f"−{len(states) - cut + 1 + offset}" for offset in range(3)]
        + [f"{observed.window_start:%H:%M}"]
        + [f"+{step}" for step in range(1, ctx.forecast_horizon + 1)],
        split_index=4,
        attack=[observed.features.get("rst_count", 0) > 0] * 4 + [False] * ctx.forecast_horizon,
    )
    st.caption(
        f"Observed through **{observed.window_start:%H:%M:%S} → {observed.window_end:%H:%M:%S}** "
        f"· {cut} of {len(states)} windows visible to the model."
    )

    result = forecast(states[:cut], ctx.loaded, max_horizon=ctx.forecast_horizon)
    peak = max(p.infiltration_probability for p in result.probability_timeline)
    lead = result.lead_time
    lead_text = (
        f"+{lead.lead_windows} win"
        if lead is not None and lead.lead_windows is not None
        else "not crossed"
    )
    ui.stats(
        [
            ui.Stat("Peak probability", f"{peak:.3f}", band=ui.band_of(peak)),
            ui.Stat("Predicted stage", result.predicted_stage.name),
            ui.Stat("Stage confidence", result.predicted_stage.confidence),
            ui.Stat("Forecast lead", lead_text),
        ]
    )
    ui.risk_meter(
        peak,
        threshold=DECISION_THRESHOLD,
        note=(
            f"Per-horizon GRU on {len(states[:cut])} observed windows · "
            f"horizon +{ctx.forecast_horizon}"
        ),
    )
    ui.stage_badge(
        result.predicted_stage.name,
        confidence=result.predicted_stage.confidence,
        mitre=(result.stage_mapping.mitre_reference if result.stage_mapping else None),
        probability=result.predicted_stage.probability,
    )

    ui.panel("Probability timeline", "Simulated ahead; nothing here has been observed yet.")
    ui.probability_timeline(
        [p.window for p in result.probability_timeline],
        [p.infiltration_probability for p in result.probability_timeline],
        threshold=DECISION_THRESHOLD,
        confidences=[p.confidence for p in result.probability_timeline],
    )
    ui.end_panel()

    mapping = result.stage_mapping
    if mapping is not None:
        ui.panel(
            f"Stage mapping — {mapping.stage}",
            mapping.rationale,
        )
        if mapping.evidence:
            ui.evidence(
                [
                    (
                        evidence.description,
                        f"{evidence.confidence:.2f}",
                    )
                    for evidence in mapping.evidence
                ]
            )
        else:
            ui.insufficient("no documented stage rule fired")
        ui.method_note(f"mapping `{mapping.mapping_version}`")
        ui.end_panel()

    ui.panel("Driving features", "Standardized feature value × fitted coefficient.")
    drivers = [(d.name, f"{d.contribution:+.3f}", d.direction) for d in result.driving_features]
    ui.evidence([(name, value) for name, value, _ in drivers], [d for _, _, d in drivers])
    ui.method_note("Exact local attribution for a linear model — not SHAP.")
    ui.end_panel()

    columns = st.columns(2)
    with columns[0]:
        ui.panel("Affected entities")
        if result.affected_entities:
            for entity in result.affected_entities[:8]:
                st.write(f"· {entity}")
        else:
            ui.empty("No entities flagged", "Nothing was attributed to a host.")
        ui.end_panel()
    with columns[1]:
        ui.panel("Caveats carried by this forecast")
        if result.warnings:
            for warning in result.warnings:
                ui.banner(warning, "", tone="degraded", icon="!")
        else:
            st.success("No caveats recorded for this forecast.")
        ui.end_panel()

    _walk_forward(ctx, scenario, states, cut)
    _trust_ledger(result)


def _walk_forward(ctx: ScreenContext, scenario: str, states: list, cut: int) -> None:
    """Score every prior position of the scenario with the same model."""
    ui.panel(
        "What the model would have said, window by window",
        "The same baseline scored at each earlier cut. The dotted line is where you are now.",
    )
    with st.spinner("Scoring prior windows…"):
        scores = [
            float(
                ctx.baseline_run.model.predict_proba(vectorize_states([state], ctx.schema))[:, 1][0]
            )
            for state in states
        ]
    figure = go.Figure(
        go.Scatter(
            x=list(range(1, len(states) + 1)),
            y=scores,
            mode="lines+markers",
            name="P(infiltration)",
            line={"color": color("risk-elevated"), "width": 2},
            marker={"size": 5},
        )
    )
    figure.add_vline(x=cut, line_dash="dot", line_color=color("risk-severe"))
    figure.add_hline(y=DECISION_THRESHOLD, line_dash="dot", line_color=color("risk-concerning"))
    figure.update_layout(
        **plotly_layout(
            height=260,
            yaxis={"range": [0, 1.05], "title": {"text": "probability"}},
            xaxis={"title": {"text": "window position"}},
        )
    )
    st.plotly_chart(figure, width="stretch")
    ui.end_panel()


def _trust_ledger(result) -> None:
    """Append-only local ledger: hashes and forecast metadata only."""
    ui.panel(
        "Trust ledger",
        "Chains forecast and evidence hashes. This is the local seam for a future "
        "permissioned chain — no raw traffic is written.",
    )
    ledger = AlertLedger(LEDGER_PATH)
    verified = ledger.verify()
    ui.stats(
        [
            ui.Stat("Registered alerts", str(verified.records_checked)),
            ui.Stat(
                "Integrity",
                "verified" if verified.valid else "FAILED",
                band=None if verified.valid else "severe",
            ),
            ui.Stat("Ledger version", "v1"),
        ]
    )
    if not verified.valid:
        for error in verified.errors:
            ui.banner(error, "", tone="error", icon="✕")

    columns = st.columns(4)
    if columns[0].button("Record alert", type="primary", key="ledger_record"):
        record = ledger.append_forecast(result)
        st.success(f"Alert {record.alert_id} registered.")
    if columns[1].button("Verify", key="ledger_verify"):
        checked = ledger.verify()
        (st.success if checked.valid else st.error)(
            f"Verified {checked.records_checked} record(s)."
            if checked.valid
            else "; ".join(checked.errors)
        )
    if columns[2].button("Simulate tampering", key="ledger_tamper"):
        if ledger.tamper_latest_for_demo():
            checked = ledger.verify()
            st.error("Tampering detected: " + "; ".join(checked.errors))
        else:
            st.warning("Record an alert before simulating tampering.")
    if columns[3].button("Reset", key="ledger_reset"):
        ledger.reset()
        st.success("Demo ledger reset.")

    records = ledger.records()
    if records:
        latest = records[-1]
        st.json(
            {
                "alert_id": latest.alert_id,
                "status": latest.status,
                "predicted_stage": latest.predicted_stage,
                "probability": latest.probability,
                "model_version": latest.model_version,
                "evidence_hash": latest.evidence_hash,
                "forecast_hash": latest.forecast_hash,
                "previous_hash": latest.previous_hash,
                "record_hash": latest.record_hash,
            }
        )
    ui.end_panel()


# ── Network states ──────────────────────────────────────────────────────


def states_screen(ctx: ScreenContext) -> None:
    """One window, in full: features, entities, edges, and the model's score."""
    scenario = ctx.select_scenario("states_scenario", "Scenario")
    if scenario is None:
        ui.empty("No scenarios", "Train on a data source first.")
        return
    states = ctx.states(scenario)
    if not states:
        ui.empty("No windows", f"{scenario} has no states.")
        return

    index = st.slider(
        "Window",
        min_value=0,
        max_value=len(states) - 1,
        value=len(states) - 1,
        help="Every index change re-renders the panel from that window's data.",
    )
    state = states[index]
    probability = float(
        ctx.baseline_run.model.predict_proba(vectorize_states([state], ctx.schema))[:, 1][0]
    )

    ui.lede(
        "A window is the unit of state: aggregated flow counters and packet "
        "headers for one interval. The model reads the standardized vector; you "
        "are reading the raw values."
    )
    ui.stats(
        [
            ui.Stat("Window", f"{state.window_start:%H:%M:%S} → {state.window_end:%H:%M:%S}"),
            ui.Stat("Events", f"{state.features.get('event_count', 0):.0f}"),
            ui.Stat(
                "Bytes", f"{state.features.get('bytes_sum', state.features.get('bytes', 0)):,.0f}"
            ),
            ui.Stat("Entities", str(len(state.entities))),
            ui.Stat("Edges", str(len(state.edge_summary))),
            ui.Stat("Model P(infiltration)", f"{probability:.3f}", band=ui.band_of(probability)),
            ui.Stat("Label", ctx.label_for(scenario, state.window_start) or "unlabelled"),
        ]
    )
    if not state.coverage.get("packet"):
        ui.degraded(
            "no packet-level events in this window",
            "TTL, TCP window, fragmentation and retransmission features are absent "
            "for this window, so packet-derived signals did not contribute.",
        )

    ui.panel("Feature values", "Log scale: real windows mix 1e5 bytes with 1e1 flag counts.")
    names = list(state.features)
    values = [max(v, 0.0) for v in state.features.values()]
    figure = go.Figure(
        go.Bar(
            x=names,
            y=values,
            marker_color=color("risk-elevated"),
            text=[f"{v:,.3g}" for v in state.features.values()],
            textposition="outside",
        )
    )
    figure.update_yaxes(type="log")
    figure.update_layout(**plotly_layout(height=340, xaxis={"tickangle": -45}, margin={"b": 90}))
    st.plotly_chart(figure, width="stretch")
    ui.end_panel()

    ui.panel("This window inside the scenario", "Moving the slider moves the marker.")
    tracked = [
        name
        for name in (
            "event_count",
            "bytes_sum",
            "bytes",
            "syn_count_sum",
            "syn_count",
            "rst_count_sum",
            "rst_count",
            "ttl_mean",
        )
        if any(name in s.features for s in states)
    ]
    figure = go.Figure()
    for offset, name in enumerate(tracked):
        figure.add_trace(
            go.Scatter(
                x=[s.window_start for s in states],
                y=[s.features.get(name, 0.0) for s in states],
                mode="lines",
                name=name,
                line={"color": _series_color(offset), "width": 1.5},
            )
        )
    figure.add_vline(x=state.window_start, line_dash="dot", line_color=color("risk-severe"))
    figure.update_yaxes(type="log")
    figure.update_layout(**plotly_layout(height=300, yaxis={"title": {"text": "value (log)"}}))
    st.plotly_chart(figure, width="stretch")
    ui.end_panel()

    with st.expander(f"Edges in this window ({len(state.edge_summary)})"):
        if state.edge_summary:
            st.dataframe(
                [
                    {
                        "source": edge["source"],
                        "destination": edge["destination"],
                        "flows": edge["count"],
                        "bytes": edge["bytes"],
                    }
                    for edge in state.edge_summary[:50]
                ],
                width="stretch",
                hide_index=True,
            )
        else:
            ui.empty("No edges", "This window contains no host-to-host activity.")


def _series_color(offset: int) -> str:
    palette = [
        color("risk-elevated"),
        color("risk-concerning"),
        color("risk-critical"),
        color("risk-quiet"),
    ]
    return palette[offset % len(palette)]


# ── Comparison ──────────────────────────────────────────────────────────


def comparison_screen(ctx: ScreenContext) -> None:
    """Baseline vs temporal, test split only."""
    baseline_test = ctx.baseline_run.result.metrics.get("test")
    temporal_test = (
        ctx.temporal_run.result.horizons[-1].metrics.get("test")
        if ctx.temporal_run.result.horizons
        else None
    )
    ui.lede(
        "Both models are trained on the same windows with the same feature "
        "schema and scored on the same held-out scenarios. The only difference "
        "is whether the model sees the sequence of windows or just the current one."
    )
    if baseline_test is None:
        ui.empty("No test metrics", "The baseline has no test-split metrics recorded.")
        return

    labels = ["Precision", "Recall", "F1", "FPR", "PR-AUC"]
    series = {
        "Baseline (current window)": [
            baseline_test.precision,
            baseline_test.recall,
            baseline_test.f1,
            baseline_test.false_positive_rate,
            baseline_test.pr_auc,
        ],
    }
    if temporal_test is not None:
        horizon = ctx.temporal_run.result.horizons[-1].horizon
        series[f"Temporal GRU h+{horizon}"] = [
            temporal_test.precision,
            temporal_test.recall,
            temporal_test.f1,
            temporal_test.false_positive_rate,
            temporal_test.pr_auc,
        ]
    ui.grouped_bars(labels, series, height=340, y_title="score")
    ui.method_note("Decision threshold as recorded in the run; PR-AUC is threshold-free.")

    if ctx.temporal_run.result.horizons:
        ui.panel("Per-horizon behaviour", "Each horizon is an independent model.")
        rows = [
            {
                "Horizon": f"+{h.horizon}",
                "Precision": h.metrics["test"].precision if "test" in h.metrics else None,
                "Recall": h.metrics["test"].recall if "test" in h.metrics else None,
                "F1": h.metrics["test"].f1 if "test" in h.metrics else None,
                "FPR": h.metrics["test"].false_positive_rate if "test" in h.metrics else None,
                "Best epoch": h.best_epoch,
            }
            for h in ctx.temporal_run.result.horizons
        ]
        st.dataframe(rows, width="stretch", hide_index=True)
        figure = go.Figure()
        for offset, metric in enumerate(("Precision", "Recall", "F1")):
            figure.add_trace(
                go.Scatter(
                    x=[row["Horizon"] for row in rows],
                    y=[row[metric] for row in rows],
                    mode="lines+markers",
                    name=metric,
                    line={"color": _series_color(offset), "width": 2},
                )
            )
        figure.update_layout(
            **plotly_layout(height=300, yaxis={"range": [0, 1.05], "title": {"text": "score"}})
        )
        st.plotly_chart(figure, width="stretch")
        ui.end_panel()


# ── Replay ──────────────────────────────────────────────────────────────


def replay_screen(ctx: ScreenContext) -> None:
    """Walk-forward replay: forecast versus what actually happened."""
    ui.observed_forecast_legend(
        "Every row: the forecast available then, against the realised future."
    )
    ui.lede(
        "For each window the forecaster is given only the history up to that "
        "point, then scored against the label that actually materialised inside "
        "the horizon. Lead time is only credited when the forecast crossed the "
        "threshold no later than the realised onset."
    )
    signature = (ctx.dataset_fingerprint, ctx.forecast_horizon, "test", 8)
    if st.session_state.get("replay_signature") != signature:
        st.session_state.pop("replay_eval", None)
        st.session_state["replay_signature"] = signature

    left, right = st.columns([3, 1])
    run = left.button("Run replay evaluation", type="primary", key="run_replay")
    if right.button("Clear", key="clear_replay"):
        st.session_state.pop("replay_eval", None)
        st.info("Cleared. Re-run for the current model and dataset.")
    if run:
        with st.spinner("Walking forward through scenarios…"):
            try:
                st.session_state["replay_eval"] = evaluate_replay(
                    ctx.labelled,
                    ctx.loaded,
                    horizon=ctx.forecast_horizon,
                    split_filter="test",
                    max_history=8,
                )
            except ValueError as error:
                st.session_state.pop("replay_eval", None)
                st.error(f"Replay could not run: {error}")

    evaluation = st.session_state.get("replay_eval")
    if evaluation is None:
        ui.empty(
            "No replay yet",
            "Run the evaluation to score forecasts against reality on the test split.",
        )
        return

    lead = evaluation.measured_median_lead_windows
    ui.stats(
        [
            ui.Stat(
                "Median lead", f"{lead:.1f} win" if lead is not None else "none", band="elevated"
            ),
            ui.Stat("Crossing rate", f"{evaluation.forecast_crossing_rate:.0%}"),
            ui.Stat("False early", f"{evaluation.false_early_warning_rate:.0%}"),
            ui.Stat(
                "Pre-onset warning",
                f"{evaluation.pre_onset_warning_rate:.0%}",
                note=f"median {evaluation.median_pre_onset_lead_windows or '—'} win",
            ),
            ui.Stat("Scenarios", str(evaluation.scenarios_evaluated)),
        ]
    )

    scenarios = sorted({summary.scenario_id for summary in evaluation.summaries})
    selected = st.selectbox("Scenario rows", scenarios, key="replay_rows_scenario")
    rows = [
        {
            "window_end": row.input_window_end,
            "peak_p": round(row.peak_probability, 3),
            "crossed": row.threshold_crossed,
            "predicted_stage": row.predicted_stage,
            "realized_stage": row.realized_future_stage,
            "lead": row.lead_windows,
            "direction_ok": row.correct_direction,
            "category": row.prediction_category,
        }
        for row in evaluation.rows
        if row.scenario_id == selected
    ]
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
        st.download_button(
            "Download analyst report (Markdown)",
            data=render_report(
                forecast(
                    ctx.states(selected),
                    ctx.loaded,
                    max_horizon=ctx.forecast_horizon,
                ),
                scenario_id=selected,
                evaluation=evaluation,
            ),
            file_name="forecast_report.md",
            mime="text/markdown",
        )
    else:
        ui.empty("No rows", f"{selected} produced no replay rows.")


# ── Guided demo ─────────────────────────────────────────────────────────


DEMO_STEPS = (
    "Normal traffic — observed",
    "Low-and-slow probing — observed",
    "Forecast: probability timeline",
    "Forecast: evidence and entities",
    "Reality check: what actually happened",
)


def demo_screen(ctx: ScreenContext) -> None:
    """A five-step story for someone who has never seen the tool."""
    ui.observed_forecast_legend("Steps 3–4 are simulated. Steps 1, 2 and 5 are measured.")
    scenarios = ctx.manifest.test_scenarios or ctx.manifest.validation_scenarios
    if not scenarios:
        ui.empty("No demo scenario", "The split has no test or validation scenario.")
        return
    scenario = st.selectbox("Replay scenario", scenarios, key="demo_scenario")
    items = ctx.labelled_for(scenario)
    states = [item.state for item in items]
    if not states:
        ui.empty("No windows", f"{scenario} has no states.")
        return

    step = st.slider("Step", 1, len(DEMO_STEPS), 1)
    st.markdown(f"**Step {step} — {DEMO_STEPS[step - 1]}**")

    count = len(states)
    baseline_cut = min(max(1, count // 3), count)
    recon_cut = min(max(baseline_cut, count // 2), count)
    history_length = baseline_cut if step == 1 else (recon_cut if step <= 4 else count)
    observed = states[history_length - 1]

    ui.stats(
        [
            ui.Stat("Observed · window end", f"{observed.window_end:%H:%M:%S}"),
            ui.Stat("Observed · events", f"{observed.features.get('event_count', 0):.0f}"),
            ui.Stat("Observed · bytes", f"{observed.features.get('bytes_sum', 0):,.0f}"),
        ]
    )

    demo_forecast = None
    if step >= 3:
        demo_forecast = forecast(states[:recon_cut], ctx.loaded, max_horizon=ctx.forecast_horizon)
        peak = max(p.infiltration_probability for p in demo_forecast.probability_timeline)
        lead = demo_forecast.lead_time
        ui.stats(
            [
                ui.Stat("Forecast · peak P", f"{peak:.3f}", band=ui.band_of(peak)),
                ui.Stat("Forecast · stage", demo_forecast.predicted_stage.name),
                ui.Stat(
                    "Forecast · lead",
                    f"+{lead.lead_windows} win"
                    if lead is not None and lead.lead_windows is not None
                    else "not crossed",
                ),
            ]
        )
        ui.probability_timeline(
            [p.window for p in demo_forecast.probability_timeline],
            [p.infiltration_probability for p in demo_forecast.probability_timeline],
            threshold=DECISION_THRESHOLD,
        )
        mapping = demo_forecast.stage_mapping
        if mapping is not None and mapping.evidence:
            ui.evidence([(e.description, f"{e.confidence:.2f}") for e in mapping.evidence])
        for warning in demo_forecast.warnings:
            ui.banner(warning, "", tone="degraded", icon="!")

    if step == 5:
        stages = [item.label.attack_stage for item in items]
        reality_index = min(baseline_cut, len(stages) - 1)
        st.markdown(
            f"**Reality (observed):** the scenario realized "
            f"{stages[reality_index]} → {stages[-1]} across the remaining windows."
        )
        if demo_forecast is not None:
            st.markdown(
                f"**Forecast made at step 3:** {demo_forecast.predicted_stage.name} "
                f"at {demo_forecast.predicted_stage.probability:.0%} — compare with the "
                "realized stage above."
            )

    st.download_button(
        "Download demo report (Markdown)",
        data=render_report(
            forecast(states[:recon_cut], ctx.loaded, max_horizon=ctx.forecast_horizon),
            scenario_id=scenario,
            dataset_id=ctx.dataset_id,
        ),
        file_name=f"demo_report_{scenario}.md",
        mime="text/markdown",
    )


# ── Metrics ─────────────────────────────────────────────────────────────


def metrics_screen(ctx: ScreenContext) -> None:
    """Model internals: what it learned, and the audit that says it is honest."""
    test = ctx.baseline_run.result.metrics.get("test")
    if test is not None:
        ui.stats(
            [
                ui.Stat("Precision", f"{test.precision:.3f}"),
                ui.Stat("Recall", f"{test.recall:.3f}"),
                ui.Stat("F1", f"{test.f1:.3f}", band=ui.band_of(test.f1 or 0.0)),
                ui.Stat("False-positive rate", f"{test.false_positive_rate:.3f}"),
                ui.Stat("PR-AUC", f"{test.pr_auc:.3f}"),
            ]
        )
        ui.method_note("Test split only. Threshold as recorded in the run.")

    ui.panel("Feature weights", "Standardized coefficient; sign is the direction of risk.")
    weights = ctx.baseline_run.result.feature_weights
    figure = go.Figure(
        go.Bar(
            x=[w.coefficient for w in weights],
            y=[w.name for w in weights],
            orientation="h",
            marker_color=[
                color("risk-critical") if w.coefficient > 0 else color("risk-quiet")
                for w in weights
            ],
        )
    )
    figure.update_layout(
        **plotly_layout(
            height=420, xaxis={"title": {"text": "coefficient"}}, yaxis={"autorange": "reversed"}
        )
    )
    st.plotly_chart(figure, width="stretch")
    ui.end_panel()

    ui.panel("Split audit", "The mechanical check that the holdout is a holdout.")
    audit = ctx.baseline_run.result.split_audit
    ui.stats(
        [
            ui.Stat(
                "Disjoint scenarios",
                "yes" if audit.disjoint_scenarios else "NO",
                band=None if audit.disjoint_scenarios else "severe",
            ),
            ui.Stat(
                "Disjoint state keys",
                "yes" if audit.disjoint_state_keys else "NO",
                band=None if audit.disjoint_state_keys else "severe",
            ),
            ui.Stat("Samples", f"{sum(audit.sample_counts.values()):,}"),
        ]
    )
    st.json(
        {
            "sample_counts": audit.sample_counts,
            "positive_counts": audit.positive_counts,
            "scenario_counts": audit.scenario_counts,
        }
    )
    ui.end_panel()

    with st.expander("Model configuration"):
        st.json(ctx.baseline_run.result.config.model_dump())


# ── Attack story ────────────────────────────────────────────────────────


def story_screen(ctx: ScreenContext) -> None:
    """Educational narrative: a credential-reuse breach, told in phases."""
    phases = dubsmash_inspired_case()
    st.session_state.setdefault("story_phase", 1)
    st.session_state.setdefault("story_contained", False)

    ui.lede(
        "An educational reconstruction of a credential-reuse breach, built from "
        "publicly reported impact. The technical path is synthetic and bounded: it "
        "does not reproduce undocumented internals and uses no real personal data."
    )
    ui.stats(
        [
            ui.Stat("Reported impact", "~161–162M accounts"),
            ui.Stat("Records", "synthetic sample"),
            ui.Stat("Pattern", "credential reuse"),
        ]
    )

    controls = st.columns(4)
    if controls[0].button("◀ Previous", key="story_prev"):
        st.session_state["story_phase"] = max(1, st.session_state["story_phase"] - 1)
    if controls[1].button("Next ▶", key="story_next"):
        st.session_state["story_phase"] = min(len(phases), st.session_state["story_phase"] + 1)
    if controls[2].button("↺ Reset", key="story_reset"):
        st.session_state["story_phase"] = 1
        st.session_state["story_contained"] = False
    if controls[3].button("⛊ Contain at firewall", key="story_contain"):
        st.session_state["story_contained"] = True

    phase_index = st.session_state["story_phase"]
    phase = phases[phase_index - 1]
    contained = st.session_state["story_contained"]
    st.progress(phase_index / len(phases), text=f"Phase {phase_index}/{len(phases)} · {phase.name}")
    if contained:
        st.success("Containment simulated: the attacker branch is blocked at the edge firewall.")
    else:
        ui.banner(
            "Demo mode — no control active",
            "The synthetic attacker continues along the visible path.",
            tone="degraded",
            icon="!",
        )

    ui.panel("1 · Network topology", "Links are observed communication, not proof of compromise.")
    nodes, edges = replay_topology(phase_index, contained=contained)
    st.plotly_chart(topology_figure(nodes, edges, active_labels={phase.name}), width="stretch")
    ui.end_panel()

    ui.panel("2 · Attack workflow")
    for column, item in zip(st.columns(len(phases)), phases, strict=True):
        with column:
            st.markdown(f"**{item.number}. {item.name}**")
            st.caption(item.summary)
            st.markdown(f"`{item.source}` → `{item.destination}`")
            st.markdown(f"`{item.protocol}:{item.port}` · {item.status}")
            for line in item.evidence:
                st.markdown(f"- {line}")
    ui.end_panel()

    ui.panel("3 · Packet and application flow")
    st.dataframe(
        [
            {
                "layer": step.layer,
                "source": step.source,
                "destination": step.destination,
                "action": step.action,
                "status": step.status,
            }
            for step in packet_flow_steps()
        ],
        width="stretch",
        hide_index=True,
    )
    ui.end_panel()

    ui.panel("4 · Attack kill chain", "Educational transition priors, not incident claims.")
    from sentinel.sequence_detector import ATTACK_TRANSITIONS

    active_types = {item.attack_type for item in phases[:phase_index]}
    st.plotly_chart(kill_chain_figure(ATTACK_TRANSITIONS, active=active_types), width="stretch")
    ui.end_panel()

    ui.panel("5 · Analyst response workflow")
    st.dataframe(
        [
            {"step": index, "phase": name, "action": action, "where": where}
            for index, (name, action, where) in enumerate(
                (
                    ("Detect", "Detector finding and alert timeline", "Live Detection"),
                    ("Triage", "Review source, asset, confidence, evidence", "Incident panel"),
                    ("Investigate", "Inspect topology, packet flow, logs", "Network States"),
                    ("Contain", "Block the observed attacker or rate-limit", "Admin blocklist"),
                    ("Recover", "Revoke sessions, rotate credentials", "Analyst-approved"),
                    ("Review", "Document the case, watch for recurrence", "Case record"),
                ),
                start=1,
            )
        ],
        width="stretch",
        hide_index=True,
    )
    ui.end_panel()

    ui.banner(
        "Resetting the demo is not remediation",
        "Clearing in-memory findings does not repair a system, erase forensic "
        "evidence, or replace credential rotation and session revocation.",
        tone="info",
        icon="›",
    )

    left, right = st.columns(2)
    with left:
        ui.stats(
            [
                ui.Stat("Phases reached", str(phase_index)),
                ui.Stat(
                    "Sensitive data path",
                    "available" if phase_index >= 4 else "not reached",
                    band="critical" if phase_index >= 4 else None,
                ),
            ]
        )
    with right:
        reached = min(phase_index, 2) if contained else phase_index
        ui.stats(
            [
                ui.Stat("Phases reached", str(reached), band="quiet" if contained else "critical"),
                ui.Stat(
                    "Sensitive data path",
                    "blocked" if contained else "available",
                    band="quiet" if contained else "critical",
                ),
            ]
        )


SCREENS = {
    "overview": overview,
    "forecast": forecast_screen,
    "states": states_screen,
    "comparison": comparison_screen,
    "replay": replay_screen,
    "demo": demo_screen,
    "metrics": metrics_screen,
    "story": story_screen,
}
