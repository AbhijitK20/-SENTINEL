"""SENTINEL Dashboard — offline interactive demo for SIH26153.

Run with:
    uv run streamlit run src/trajectory/dashboard/app.py

No cloud APIs required. All inference runs from saved local artifacts.
"""

from __future__ import annotations

import platform
import subprocess
import sys
import time
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from trajectory.baseline import SPLIT_NAMES, train_baseline
from trajectory.config import BaselineConfig
from trajectory.dashboard.live_artifacts import select_live_artifacts
from trajectory.evaluation import evaluate_replay
from trajectory.features import fit_feature_schema
from trajectory.ledger import AlertLedger
from trajectory.live import (
    CsvReplaySource,
    EventReplaySource,
    JsonlSensorSource,
    LiveEngine,
    ScapyInterfaceSource,
)
from trajectory.predict import DECISION_THRESHOLD, artifacts_from_runs, forecast
from trajectory.report import render_report
from trajectory.synthetic import generate_labelled_states, generate_scenario_events
from trajectory.targets import build_sequence_samples, make_split_manifest
from trajectory.temporal import TemporalConfig, train_temporal

ROOT = Path(__file__).resolve().parent.parent.parent.parent
REPORTS_DIR = ROOT / "reports" / "generated"
LEDGER_PATH = REPORTS_DIR / "ledger" / "alerts.jsonl"
LOCAL_ATTACK_SPEED = 2.0
DEFAULT_SCENARIOS = [f"scenario-{index:02d}" for index in range(1, 11)]

# ── Page Config ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="SENTINEL — SIH26153",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar ───────────────────────────────────────────────────────────
with st.sidebar:
    st.title("SENTINEL")
    st.caption("SIH26153 — AI Network Attack Forecasting")
    st.divider()
    st.subheader("Settings")
    scenario_count = st.slider("Scenarios", min_value=3, max_value=15, value=6)
    seed = st.number_input("Seed", min_value=0, max_value=9999, value=42)
    window_seconds = st.number_input("Window (s)", min_value=10, max_value=300, value=60)
    stride_seconds = st.number_input("Stride (s)", min_value=5, max_value=300, value=30)
    sequence_length = st.number_input("Sequence length", min_value=2, max_value=16, value=8)
    forecast_horizon = st.number_input("Forecast horizon", min_value=1, max_value=10, value=5)
    st.divider()
    st.subheader("Models")
    full_training = st.checkbox(
        "Full temporal training (slower)",
        value=False,
        help="Leave off for the hosted demo. Full mode trains more GRU horizons and epochs.",
    )
    train_btn = st.button("Train / Retrain", type="primary")
    st.divider()
    st.caption(f"Python {sys.version.split()[0]} · {platform.system()}")


# ── Caching ───────────────────────────────────────────────────────────
@st.cache_data
def generate_data(
    scenario_count: int,
    seed: int,
    window_seconds: int,
    stride_seconds: int,
    sequence_length: int,
    forecast_horizon: int,
) -> tuple:
    scenario_ids = DEFAULT_SCENARIOS[:scenario_count]
    labelled = generate_labelled_states(
        scenario_ids,
        seed=seed,
        window_seconds=window_seconds,
        stride_seconds=stride_seconds,
    )
    samples = build_sequence_samples(
        labelled,
        sequence_length=sequence_length,
        horizon=forecast_horizon,
    )
    manifest = make_split_manifest(scenario_ids, seed=seed)
    return labelled, samples, manifest


@st.cache_resource
def train_models(
    labelled,
    samples,
    manifest,
    seed: int,
    forecast_horizon: int,
    full_training: bool,
):
    config = BaselineConfig()
    baseline_run = train_baseline(labelled, samples, manifest, config=config, seed=seed)

    train_states = [item.state for item in labelled if item.scenario_id in manifest.train_scenarios]
    schema = fit_feature_schema(
        train_states,
        excluded_features=config.excluded_features,
    )

    temporal_config = TemporalConfig(
        hidden_size=32 if full_training else 16,
        num_layers=1,
        max_epochs=50 if full_training else 12,
        early_stopping_patience=8 if full_training else 3,
    )
    temporal_run = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=schema,
        config=temporal_config,
        seed=seed,
        max_horizon=min(forecast_horizon, 5 if full_training else 3),
    )
    return baseline_run, temporal_run, schema


# ── Main ──────────────────────────────────────────────────────────────
st.title("🛡️ SENTINEL — Network Attack Forecasting Dashboard")

# Generate data
labelled, samples, manifest = generate_data(
    scenario_count,
    int(seed),
    int(window_seconds),
    int(stride_seconds),
    int(sequence_length),
    int(forecast_horizon),
)

# Train on button click
if train_btn:
    with st.spinner("Training baseline + temporal model..."):
        baseline_run, temporal_run, schema = train_models(
            labelled,
            samples,
            manifest,
            int(seed),
            int(forecast_horizon),
            full_training,
        )
    st.session_state["baseline_run"] = baseline_run
    st.session_state["temporal_run"] = temporal_run
    st.session_state["schema"] = schema
    st.success(
        f"Training complete in {baseline_run.result.training_seconds * 1000:.1f}ms (baseline)"
    )
    st.rerun()

# Check if trained
if "baseline_run" not in st.session_state:
    st.info("Click **Train / Retrain** in the sidebar to start.")
    st.stop()

baseline_run = st.session_state.get("baseline_run")
temporal_run = st.session_state.get("temporal_run")
schema = st.session_state.get("schema")

# In-memory artifacts for the inference layer, including the trained
# per-horizon temporal weights when available.
loaded = artifacts_from_runs(baseline_run, temporal_run=temporal_run)

# ── Tabs ──────────────────────────────────────────────────────────────
tab_overview, tab_forecast, tab_states, tab_compare, tab_replay, tab_demo, tab_live, tab_metrics = (
    st.tabs(
        [
            "Overview",
            "Forecast",
            "Network States",
            "Comparison",
            "Replay",
            "Demo",
            "Live Detection",
            "Metrics",
        ]
    )
)

# ── Tab: Overview ─────────────────────────────────────────────────────
with tab_overview:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Scenarios", scenario_count)
    col2.metric("Train", len(manifest.train_scenarios))
    col3.metric("Val", len(manifest.validation_scenarios))
    col4.metric("Test", len(manifest.test_scenarios))

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total States", len(labelled))
    col2.metric("Sequence Samples", len(samples))
    col3.metric("Features", schema.width)
    col4.metric("Horizon", forecast_horizon)

    st.subheader("Split Distribution")
    split_counts = {
        name: sum(1 for s in labelled if s.scenario_id in getattr(manifest, f"{name}_scenarios"))
        for name in SPLIT_NAMES
    }
    fig = go.Figure(
        data=[
            go.Bar(
                x=list(split_counts.keys()),
                y=list(split_counts.values()),
                marker_color=["#6dd3a8", "#6ea8ff", "#f0c674"],
                text=list(split_counts.values()),
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=300,
        showlegend=False,
        yaxis_title="States",
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Attack Stage Distribution")
    stage_counts = {}
    for item in labelled:
        stage = item.label.attack_stage
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
    fig2 = go.Figure(
        data=[
            go.Pie(
                labels=list(stage_counts.keys()),
                values=list(stage_counts.values()),
                marker_colors=["#6dd3a8", "#f0c674", "#ef6f6f"],
                hole=0.4,
            )
        ]
    )
    fig2.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=300,
        showlegend=True,
    )
    st.plotly_chart(fig2, use_container_width=True)

# ── Tab: Forecast ─────────────────────────────────────────────────────
with tab_forecast:
    scenario_split = {
        scenario: split
        for split in SPLIT_NAMES
        for scenario in getattr(manifest, f"{split}_scenarios")
    }
    all_scenarios = sorted(scenario_split)
    scenario_choice = st.selectbox(
        "Select scenario for forecast",
        all_scenarios,
        format_func=lambda scenario: f"{scenario} ({scenario_split[scenario]})",
    )
    st.caption(
        f"Showing all {len(all_scenarios)} scenarios. The split label is shown so you "
        "can explore training, validation, and test behavior; Replay evaluation "
        "remains test-only for an honest holdout measurement."
    )
    scenario_states = [item.state for item in labelled if item.scenario_id == scenario_choice]

    if not scenario_states:
        st.warning("No states found for this scenario.")
        st.stop()

    result = forecast(
        scenario_states,
        loaded,
        max_horizon=forecast_horizon,
    )

    # Header
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Peak Probability", f"{result.predicted_stage.probability:.1%}")
    col2.metric("Predicted Stage", result.predicted_stage.name)
    col3.metric("Confidence", result.predicted_stage.confidence)
    lead = result.lead_time
    lead_text = (
        f"+{lead.lead_windows} win"
        if lead is not None and lead.lead_windows is not None
        else "not crossed"
    )
    col4.metric("Forecast Lead", lead_text)

    # Stage mapping with documented evidence
    if result.stage_mapping is not None:
        mapping = result.stage_mapping
        st.subheader("Stage Mapping — Documented Rules")
        st.markdown(
            f"**{mapping.stage}** · {mapping.mitre_reference or 'no MITRE reference'} "
            f"· confidence: {mapping.confidence} · `{mapping.mapping_version}`"
        )
        st.caption(mapping.rationale)
        if mapping.evidence:
            for ev in mapping.evidence:
                value = (
                    f" (observed {ev.observed_value:.1f})" if ev.observed_value is not None else ""
                )
                st.markdown(f"- {ev.description}{value} · confidence {ev.confidence:.2f}")
        else:
            st.info(
                "No documented rule fired on this window: insufficient evidence "
                "for a stage hypothesis."
            )

    # Timeline
    st.subheader("Forecast Probability Timeline")
    windows = [p.window for p in result.probability_timeline]
    probs = [p.infiltration_probability for p in result.probability_timeline]
    confs = [p.confidence for p in result.probability_timeline]

    fig3 = go.Figure()
    fig3.add_trace(
        go.Scatter(
            x=windows,
            y=probs,
            mode="lines+markers",
            name="P(infiltration)",
            line=dict(color="#6dd3a8", width=3),
            marker=dict(size=8),
        )
    )
    fig3.add_hline(
        y=DECISION_THRESHOLD,
        line_dash="dash",
        line_color="#f0c674",
        annotation_text=f"Threshold = {DECISION_THRESHOLD}",
    )
    fig3.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=350,
        xaxis_title="Forecast Window",
        yaxis_title="Probability",
        yaxis_range=[0, 1.05],
    )
    st.plotly_chart(fig3, use_container_width=True)

    # Driving features
    st.subheader("Driving Features")
    feat_names = [f.name for f in result.driving_features]
    feat_contribution = [f.contribution for f in result.driving_features]
    feat_colors = ["#6dd3a8" if c > 0 else "#ef6f6f" for c in feat_contribution]

    fig4 = go.Figure(
        data=[
            go.Bar(
                x=feat_contribution,
                y=feat_names,
                orientation="h",
                marker_color=feat_colors,
                text=[f"{c:+.3f}" for c in feat_contribution],
                textposition="auto",
            )
        ]
    )
    fig4.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=300,
        xaxis_title="Contribution (std × coefficient)",
        yaxis=dict(autorange="reversed"),
    )
    st.plotly_chart(fig4, use_container_width=True)

    # Affected entities
    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Affected Entities")
        for entity in result.affected_entities[:8]:
            st.write(f"- {entity}")

    with col_b:
        st.subheader("Warnings")
        if result.warnings:
            for w in result.warnings:
                st.warning(w)
        else:
            st.success("No warnings")

    # Blockchain-theme integrity layer: only hashes and forecast metadata are
    # recorded; raw traffic and sensitive evidence remain off-ledger.
    st.subheader("Trust Ledger")
    st.caption(
        "This local append-only ledger chains forecast and evidence hashes. "
        "It is the prototype boundary for a future permissioned blockchain."
    )
    ledger = AlertLedger(LEDGER_PATH)
    verify_result = ledger.verify()
    ledger_col1, ledger_col2, ledger_col3 = st.columns(3)
    ledger_col1.metric("Registered Alerts", verify_result.records_checked)
    ledger_col2.metric("Integrity", "Verified" if verify_result.valid else "Failed")
    ledger_col3.metric("Ledger Version", "v1")
    if verify_result.valid:
        st.success("Forecast ledger integrity verified.")
    else:
        for error in verify_result.errors:
            st.error(error)

    action_col, verify_col, tamper_col, reset_col = st.columns(4)
    with action_col:
        if st.button("Record Alert", type="primary"):
            record = ledger.append_forecast(result)
            st.session_state["last_alert_id"] = record.alert_id
            st.success(f"Alert {record.alert_id} registered in the trust ledger.")
    with verify_col:
        if st.button("Verify Ledger"):
            checked = ledger.verify()
            if checked.valid:
                st.success(f"Verified {checked.records_checked} ledger record(s).")
            else:
                st.error("Ledger verification failed: " + "; ".join(checked.errors))
    with tamper_col:
        if st.button("Simulate Tampering"):
            if ledger.tamper_latest_for_demo():
                checked = ledger.verify()
                st.error(
                    "Tampering detected: " + "; ".join(checked.errors)
                    if not checked.valid
                    else "Unexpectedly verified; refresh and try again."
                )
            else:
                st.warning("Record an alert before simulating tampering.")
    with reset_col:
        if st.button("Reset Demo Ledger"):
            ledger.reset()
            st.success("Demo ledger reset. Record a new alert to start again.")

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

# ── Tab: Network States ──────────────────────────────────────────────
with tab_states:
    st.subheader(f"Network States — {scenario_choice}")
    st.write(f"Total states: {len(scenario_states)}")

    selected_idx = st.slider(
        "State index", min_value=0, max_value=len(scenario_states) - 1, value=0
    )
    state = scenario_states[selected_idx]

    col1, col2 = st.columns(2)
    with col1:
        st.json(
            {
                "window_start": state.window_start.isoformat(),
                "window_end": state.window_end.isoformat(),
                "entities": state.entities,
                "source_ids_count": len(state.source_ids),
            }
        )
    with col2:
        st.json(state.coverage)

    st.subheader("Feature Values")
    feat_names = list(state.features.keys())
    feat_vals = list(state.features.values())
    fig5 = go.Figure(
        data=[
            go.Bar(
                x=feat_names,
                y=feat_vals,
                marker_color="#6ea8ff",
            )
        ]
    )
    fig5.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=300,
        xaxis_tickangle=-45,
    )
    st.plotly_chart(fig5, use_container_width=True)

    # Entity timeline across all states
    st.subheader("Entity Activity Over Time")
    entity_counts = []
    for s in scenario_states:
        entity_counts.append(
            {
                "time": s.window_start.isoformat(),
                "entities": len(s.entities),
                "events": s.features.get("event_count", 0),
                "bytes": s.features.get("bytes", 0),
            }
        )

    fig6 = go.Figure()
    times = [e["time"] for e in entity_counts]
    fig6.add_trace(
        go.Scatter(
            x=times,
            y=[e["entities"] for e in entity_counts],
            mode="lines+markers",
            name="Entities",
            line=dict(color="#6dd3a8", width=2),
        )
    )
    fig6.add_trace(
        go.Scatter(
            x=times,
            y=[e["events"] for e in entity_counts],
            mode="lines",
            name="Events",
            line=dict(color="#6ea8ff", width=2),
        )
    )
    fig6.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=300,
        xaxis_title="Time",
        yaxis_title="Count",
    )
    st.plotly_chart(fig6, use_container_width=True)

# ── Tab: Comparison ──────────────────────────────────────────────────
with tab_compare:
    st.subheader("Baseline vs Temporal — Test Split")

    baseline_test = baseline_run.result.metrics.get("test")
    temporal_test = None
    if temporal_run.result.horizons:
        temporal_test = temporal_run.result.horizons[-1].metrics.get("test")

    if baseline_test:
        metrics_data = {
            "Metric": ["Precision", "Recall", "F1", "FPR", "PR-AUC"],
            "Baseline": [
                baseline_test.precision,
                baseline_test.recall,
                baseline_test.f1,
                baseline_test.false_positive_rate,
                baseline_test.pr_auc,
            ],
        }
        if temporal_test:
            metrics_data["Temporal"] = [
                temporal_test.precision,
                temporal_test.recall,
                temporal_test.f1,
                temporal_test.false_positive_rate,
                temporal_test.pr_auc,
            ]

        fig7 = go.Figure()
        fig7.add_trace(
            go.Bar(
                x=metrics_data["Metric"],
                y=metrics_data["Baseline"],
                name="Baseline",
                marker_color="#f0c674",
                text=[f"{v:.3f}" if v is not None else "n/a" for v in metrics_data["Baseline"]],
                textposition="auto",
            )
        )
        if "Temporal" in metrics_data:
            fig7.add_trace(
                go.Bar(
                    x=metrics_data["Metric"],
                    y=metrics_data["Temporal"],
                    name="Temporal h+5",
                    marker_color="#6dd3a8",
                    text=[f"{v:.3f}" if v is not None else "n/a" for v in metrics_data["Temporal"]],
                    textposition="auto",
                )
            )
        fig7.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0b0d12",
            plot_bgcolor="#0b0d12",
            barmode="group",
            height=400,
            yaxis_range=[0, 1.1],
        )
        st.plotly_chart(fig7, use_container_width=True)
    else:
        st.warning("No test metrics available")

    # Per-horizon temporal metrics
    if temporal_run.result.horizons:
        st.subheader("Temporal Model — Per-Horizon Metrics")
        horizon_data = []
        for h in temporal_run.result.horizons:
            test_m = h.metrics.get("test")
            if test_m:
                horizon_data.append(
                    {
                        "Horizon": f"+{h.horizon}",
                        "Precision": test_m.precision,
                        "Recall": test_m.recall,
                        "F1": test_m.f1,
                        "FPR": test_m.false_positive_rate,
                        "PR-AUC": test_m.pr_auc,
                        "Epochs": h.best_epoch,
                    }
                )

        if horizon_data:
            fig8 = go.Figure()
            for metric_name, color in [
                ("Precision", "#6dd3a8"),
                ("Recall", "#6ea8ff"),
                ("F1", "#f0c674"),
            ]:
                vals = [d[metric_name] for d in horizon_data]
                fig8.add_trace(
                    go.Scatter(
                        x=[d["Horizon"] for d in horizon_data],
                        y=vals,
                        mode="lines+markers",
                        name=metric_name,
                        line=dict(color=color, width=3),
                        marker=dict(size=8),
                    )
                )
            fig8.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0b0d12",
                plot_bgcolor="#0b0d12",
                height=350,
                yaxis_range=[0, 1.1],
                xaxis_title="Horizon",
                yaxis_title="Score",
            )
            st.plotly_chart(fig8, use_container_width=True)

# ── Tab: Replay ──────────────────────────────────────────────────────
with tab_replay:
    st.subheader("Walk-Forward Replay — Forecast vs Reality")
    st.caption(
        "Every window of the selected split gets the forecast that was available "
        "at that moment, scored against the label that actually realized within "
        "the horizon."
    )

    if st.button("Run replay evaluation"):
        with st.spinner("Walking forward through scenarios..."):
            st.session_state["replay_eval"] = evaluate_replay(
                labelled,
                loaded,
                horizon=forecast_horizon,
                split_filter="test",
                max_history=8,
            )

    replay_eval = st.session_state.get("replay_eval")
    if replay_eval is None:
        st.info("Click **Run replay evaluation** to score forecasts against reality.")
    else:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric(
            "Measured Median Lead",
            (
                f"{replay_eval.measured_median_lead_windows:.1f} win"
                if replay_eval.measured_median_lead_windows is not None
                else "none"
            ),
        )
        col2.metric("Crossing Rate", f"{replay_eval.forecast_crossing_rate:.0%}")
        col3.metric("False Early Rate", f"{replay_eval.false_early_warning_rate:.0%}")
        col4.metric("Scenarios", replay_eval.scenarios_evaluated)

        st.markdown("#### Forecast vs Reality (rows)")
        replay_scenarios = sorted({s.scenario_id for s in replay_eval.summaries})
        selected_replay_scenario = st.selectbox(
            "Scenario",
            replay_scenarios,
            key="replay_row_scenario",
        )
        rows_data = [
            {
                "scenario": row.scenario_id,
                "window_end": row.input_window_end,
                "peak_p": round(row.peak_probability, 3),
                "crossed": row.threshold_crossed,
                "predicted_stage": row.predicted_stage,
                "realized_stage": row.realized_future_stage,
                "lead": row.lead_windows,
                "direction_ok": row.correct_direction,
            }
            for row in replay_eval.rows
            if row.scenario_id == selected_replay_scenario
        ]
        st.dataframe(rows_data, use_container_width=True, hide_index=True)

        if rows_data:
            report_md = render_report(
                forecast(
                    [i.state for i in labelled if i.scenario_id == selected_replay_scenario],
                    loaded,
                    max_horizon=forecast_horizon,
                ),
                scenario_id=selected_replay_scenario,
                evaluation=replay_eval,
            )
            st.download_button(
                "Download analyst report (Markdown)",
                data=report_md,
                file_name="forecast_report.md",
                mime="text/markdown",
            )
        else:
            st.warning("No replay rows are available for the selected scenario.")

# ── Tab: Demo ────────────────────────────────────────────────────
with tab_demo:
    st.subheader("Two-Minute Guided Demo — Deterministic Replay")
    st.caption(
        "Observed values come from replayed windows; forecasts come from the "
        "model. The replay is deterministic for a fixed seed: restart and the "
        "same story repeats."
    )

    demo_scenarios = manifest.test_scenarios or manifest.validation_scenarios
    demo_scenario = st.selectbox("Replay scenario", demo_scenarios, key="demo_scenario")
    demo_labelled = [item for item in labelled if item.scenario_id == demo_scenario]
    demo_states = [item.state for item in demo_labelled]

    demo_steps = [
        "1. Normal baseline traffic (observed)",
        "2. Reconnaissance begins (observed)",
        "3. Forecast: probability timeline (forecast)",
        "4. Evidence and affected entities (forecast)",
        "5. Reality check: what actually happened next (observed)",
    ]
    demo_step = st.slider("Demo step", 1, len(demo_steps), 1)
    st.markdown(f"**{demo_steps[demo_step - 1]}**")

    # Deterministic replay position: fixed fractions of the scenario length.
    baseline_cut = max(1, len(demo_states) // 3)
    recon_cut = max(baseline_cut + 1, len(demo_states) // 2)
    if demo_step == 1:
        history_len = baseline_cut
    elif demo_step in (2, 3, 4):
        history_len = recon_cut
    else:
        history_len = len(demo_states)

    observed = demo_states[history_len - 1]
    c1, c2, c3 = st.columns(3)
    c1.metric("OBSERVED · window end", observed.window_end.strftime("%H:%M:%S"))
    c2.metric("OBSERVED · events in window", f"{observed.features.get('event_count', 0):.0f}")
    c3.metric("OBSERVED · bytes in window", f"{observed.features.get('bytes', 0):.0f}")

    demo_forecast = None
    if demo_step >= 3:
        demo_forecast = forecast(demo_states[:recon_cut], loaded, max_horizon=forecast_horizon)
        d1, d2, d3 = st.columns(3)
        peak = max(p.infiltration_probability for p in demo_forecast.probability_timeline)
        d1.metric(
            "FORECAST · peak P(infiltration)",
            f"{peak:.1%}",
        )
        d2.metric("FORECAST · predicted stage", demo_forecast.predicted_stage.name)
        d3.metric(
            "FORECAST · lead",
            (
                f"+{demo_forecast.lead_time.lead_windows} win"
                if demo_forecast.lead_time is not None
                and demo_forecast.lead_time.lead_windows is not None
                else "not crossed"
            ),
        )
        if demo_forecast.stage_mapping is not None:
            mapping = demo_forecast.stage_mapping
            st.markdown(
                f"Stage mapping: **{mapping.stage}** · "
                f"{mapping.mitre_reference or 'no MITRE reference'} · "
                f"`{mapping.mapping_version}`"
            )
            for ev in mapping.evidence:
                st.markdown(f"- {ev.description} · confidence {ev.confidence:.2f}")
        if demo_forecast.warnings:
            for w in demo_forecast.warnings:
                st.warning(w)

    if demo_step == 5:
        realized_stages = [item.label.attack_stage for item in demo_labelled]
        st.markdown(
            f"**Reality:** the scenario realized stages "
            f"{realized_stages[baseline_cut]} → {realized_stages[-1]} over the "
            "remaining windows (observed labels)."
        )
        if demo_forecast is not None:
            st.markdown(
                f"**Forecast made at step 3:** {demo_forecast.predicted_stage.name} "
                f"({demo_forecast.predicted_stage.probability:.1%}) — compare with "
                "the realized stage above."
            )

    st.download_button(
        "Download demo report (Markdown)",
        data=render_report(
            forecast(demo_states[:recon_cut], loaded, max_horizon=forecast_horizon),
            scenario_id=demo_scenario,
            dataset_id="synthetic-recon-lateral-v1",
        ),
        file_name=f"demo_report_{demo_scenario}.md",
        mime="text/markdown",
    )

# ── Tab: Metrics ───────────────────────────────────────────────────
with tab_metrics:
    st.subheader("Baseline Metrics")
    if baseline_test:
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Precision", f"{baseline_test.precision:.3f}")
        m2.metric("Recall", f"{baseline_test.recall:.3f}")
        m3.metric("F1", f"{baseline_test.f1:.3f}")
        m4.metric("FPR", f"{baseline_test.false_positive_rate:.3f}")
        m5.metric("PR-AUC", f"{baseline_test.pr_auc:.3f}")

    st.subheader("Feature Weights (Standardized)")
    weights = baseline_run.result.feature_weights
    fig9 = go.Figure(
        data=[
            go.Bar(
                x=[w.coefficient for w in weights],
                y=[w.name for w in weights],
                orientation="h",
                marker_color=["#6dd3a8" if w.coefficient > 0 else "#ef6f6f" for w in weights],
            )
        ]
    )
    fig9.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=400,
        xaxis_title="Coefficient",
        yaxis=dict(autorange="reversed"),
    )
    st.plotly_chart(fig9, use_container_width=True)

    st.subheader("Split Audit")
    audit = baseline_run.result.split_audit
    st.json(
        {
            "sample_counts": audit.sample_counts,
            "positive_counts": audit.positive_counts,
            "scenario_counts": audit.scenario_counts,
            "disjoint_scenarios": audit.disjoint_scenarios,
            "disjoint_state_keys": audit.disjoint_state_keys,
        }
    )

    st.subheader("Model Config")
    st.json(baseline_run.result.config.model_dump())


# ── Tab: Live Detection ──────────────────────────────────────────────
@st.fragment(run_every=2.0)
def _live_poll_fragment() -> None:
    """Auto-refreshing live status: polls the engine and redraws."""
    engine = st.session_state.get("live_engine")
    if engine is None:
        return
    _render_live_status(engine.poll())


def _render_live_status(status) -> None:
    """Draw one LiveStatus snapshot. OBSERVED = window features, FORECAST = model."""
    latest = status.history[-1] if status.history else None
    peak = max(status.history, key=lambda window: window.probability) if status.history else None
    alert = peak is not None and peak.probability >= peak.threshold

    if alert:
        st.error(
            f"🚨 **ALERT observed — {peak.stage}** · peak P(infiltration) = "
            f"{peak.probability:.2f} ≥ threshold {peak.threshold:.2f} · "
            f"{peak.mitre_reference or 'stage evidence only'}"
        )
        if latest is not None and latest is not peak:
            st.caption(
                f"Current window: {latest.stage}, P(infiltration) = {latest.probability:.2f}. "
                "The alert remains visible because it was observed earlier in the replay."
            )
    else:
        st.success(
            f"✅ Monitoring — last window {latest.event_count} events · "
            f"P(infiltration) = {latest.probability:.2f}"
            if latest
            else "Waiting for the first window…"
        )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Events seen", status.events_seen)
    col2.metric("Windows", status.windows_emitted)
    col3.metric("Current stage", latest.stage if latest else "—")
    col4.metric("Peak probability", f"{peak.probability:.2f}" if peak else "—")
    st.caption(
        f"Alert status: **{status.alert_status.replace('-', ' ').title()}** · "
        f"{status.windows_emitted} completed window(s)"
    )
    if peak is not None and not alert:
        st.warning(
            f"Peak live probability was {peak.probability:.2f}, below the "
            f"{status.threshold:.2f} alert threshold. Current stage evidence is "
            f"{latest.stage if latest else 'not available'}; stage evidence alone "
            "does not trigger an alert."
        )

    if status.running and latest is None:
        st.info(
            "Attack replay is running. Waiting for the first completed time window... "
            f"Events received: {status.events_seen}."
        )

    if status.history:
        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=[w.window_end for w in status.history],
                y=[w.probability for w in status.history],
                mode="lines+markers",
                name="P(infiltration)",
                text=[f"{w.probability:.2f}" for w in status.history],
                textposition="top center",
                customdata=[[w.stage, w.event_count] for w in status.history],
                hovertemplate=(
                    "Window end: %{x}<br>"
                    "P(infiltration): %{y:.3f}<br>"
                    "Stage: %{customdata[0]}<br>"
                    "Events: %{customdata[1]}<extra></extra>"
                ),
                line=dict(color="#6dd3a8", width=3),
                marker=dict(size=8),
            )
        )
        if peak is not None:
            fig.add_trace(
                go.Scatter(
                    x=[peak.window_end],
                    y=[peak.probability],
                    mode="markers+text",
                    name="Peak observed",
                    text=[f"Peak {peak.probability:.2f}"],
                    textposition="bottom center",
                    marker=dict(color="#ef6f6f", size=14, symbol="star"),
                    hovertemplate="Peak observed: %{y:.3f}<extra></extra>",
                )
            )
        fig.add_hline(y=status.threshold, line_dash="dot", annotation_text="threshold")
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0b0d12",
            plot_bgcolor="#0b0d12",
            title="Live probability timeline",
            xaxis_title="Event time",
            yaxis=dict(range=[0, 1], title="P(infiltration)"),
            height=380,
        )
        st.plotly_chart(fig, use_container_width=True, key="live-timeline")

        with st.expander("Stage evidence (latest window)", expanded=alert):
            if latest.stage_evidence:
                for ev in latest.stage_evidence:
                    observed = (
                        f" — observed {ev.observed_value:g}"
                        if ev.observed_value is not None
                        else ""
                    )
                    st.markdown(f"- **{ev.name}**{observed} · confidence {ev.confidence:.2f}")
                    st.caption(ev.description)
            else:
                st.caption("No evidence rules fired for the latest window.")

        if latest.warnings:
            with st.expander("Forecast warnings", expanded=False):
                for warning in latest.warnings:
                    if "below the decision threshold" in warning and alert:
                        st.info(
                            "The latest window is below threshold, but an earlier live window "
                            "crossed it; the alert above is retained."
                        )
                    else:
                        st.warning(warning)

    if status.last_error:
        st.warning(f"Source error: {status.last_error}")
    if not status.running:
        if peak is not None and alert:
            st.info("Replay finished. The peak alert above was observed during the replay.")
        else:
            st.info("Replay finished without crossing the threshold. Press **Start** to run again.")


def _make_source(
    mode: str,
    *,
    uploaded_file=None,
    replay_speed: float = 60.0,
    capture_interface: str = "lo",
):
    """Build the event source selected in the Live tab."""
    if mode == "Synthetic attack replay":
        # Use the complete deterministic attack story. The live engine keeps a
        # bounded history, but does not truncate this replay into a short demo.
        events, _ = generate_scenario_events("hosted-demo", seed=int(seed))
        return EventReplaySource(events, speed=replay_speed)
    if mode == "CSV replay":
        if uploaded_file is None:
            raise ValueError("Upload a CICFlowMeter CSV before starting the replay")
        import tempfile

        handle = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        handle.write(uploaded_file.getvalue())
        handle.close()
        return CsvReplaySource(handle.name, speed=replay_speed)
    if mode == "Local loopback capture":
        return ScapyInterfaceSource(capture_interface.strip() or "lo")
    if uploaded_file is None:
        raise ValueError("Upload a JSONL sensor file before starting the replay")
    import tempfile

    handle = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="wb")
    handle.write(uploaded_file.getvalue())
    handle.close()
    return JsonlSensorSource(handle.name, scenario_id="uploaded-sensor", follow=False)


def _local_attack_demo_available() -> bool:
    """Return whether the app is running where the localhost demo can execute."""
    return not Path("/mount/src").exists()


def _start_local_attack_demo() -> JsonlSensorSource:
    """Start the harmless localhost target/attack pair and return its sensor source."""
    events_path = ROOT / "reports" / "live" / "events.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.write_text("", encoding="utf-8")

    target = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "attack_demo.py"), "target"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    time.sleep(0.2)
    attack = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts" / "attack_demo.py"),
            "attack",
            "--events",
            str(events_path),
            "--speed",
            str(LOCAL_ATTACK_SPEED),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    st.session_state["local_attack_processes"] = (target, attack)
    return JsonlSensorSource(events_path, scenario_id="local-attack-demo", follow=True)


def _stop_local_attack_demo() -> None:
    """Stop local demo child processes without affecting hosted replay."""
    for process in st.session_state.pop("local_attack_processes", ()):
        if process.poll() is None:
            process.terminate()


with tab_live:
    st.subheader("Live Detection")
    st.caption(
        "Rolling windows over streaming events, scored by the same trained "
        "models as every other tab. OBSERVED = aggregated window features; "
        "FORECAST = model probability. Hosted replay is synthetic and safe — "
        "it never exploits anything."
    )
    st.caption(
        "Stage evidence describes observed behavior; an alert is raised only when "
        "the peak infiltration probability crosses the threshold."
    )

    mode = st.radio(
        "Event source",
        [
            "Synthetic attack replay",
            "CSV replay",
            "JSONL sensor file",
            "Local loopback capture",
        ],
        horizontal=True,
        key="live-mode",
    )

    col_a, col_b, col_c = st.columns(3)
    live_window = col_a.number_input("Window (s)", 10, 300, 60, key="live-window")
    live_stride = col_b.number_input("Stride (s)", 5, 300, 30, key="live-stride")
    live_threshold = col_c.number_input(
        "Threshold",
        0.05,
        0.95,
        float(DECISION_THRESHOLD),
        0.05,
        key="live-threshold",
    )
    replay_speed = st.slider("Replay speed (simulated seconds / real second)", 1.0, 600.0, 60.0)
    uploaded_file = None
    capture_interface = "lo"
    if mode == "CSV replay":
        uploaded_file = st.file_uploader(
            "Upload a CICFlowMeter CSV", type=["csv"], key="live-csv-upload"
        )
        st.caption("The CSV must use the supported CICFlowMeter columns and labels.")
    elif mode == "JSONL sensor file":
        uploaded_file = st.file_uploader(
            "Upload a JSONL sensor file", type=["jsonl", "txt"], key="live-jsonl-upload"
        )
        st.caption("Each line must contain timestamp, src, dst, and optional features.")
    elif mode == "Local loopback capture":
        capture_interface = st.text_input(
            "Capture interface",
            value="lo",
            help="Linux loopback is usually 'lo'. Scapy and capture privileges are required.",
        )
        st.warning(
            "Packet capture runs on the machine hosting this dashboard. It observes packets "
            "only and does not generate traffic. Local Linux privileges and the "
            "pcap extra are required."
        )

    if mode == "Synthetic attack replay":
        st.info(
            "This is a safe simulated attack. Click the button to initiate "
            "benign traffic → reconnaissance → lateral movement. "
            "The complete deterministic replay runs through all three phases. "
            "The attack alert threshold is 0.50."
        )
        if _local_attack_demo_available():
            st.caption("Initiate runs the exact local target and attack scripts at speed 2.")
        else:
            st.caption(
                "This button requires the local SENTINEL dashboard; hosted Streamlit "
                "cannot start localhost attack scripts."
            )
    col1, col2, col3 = st.columns(3)
    start_requested = col1.button("▶ Start", type="primary", key="live-start")
    attack_requested = col2.button("🚨 Initiate Attack", type="primary", key="live-attack")
    stop_requested = col3.button("■ Stop", key="live-stop")

    if start_requested or attack_requested:
        try:
            if attack_requested:
                if not _local_attack_demo_available():
                    raise RuntimeError(
                        "The local attack scripts can only run on the machine hosting "
                        "Streamlit. Run SENTINEL locally for this button."
                    )
                _stop_local_attack_demo()
                # Match the documented fast local command exactly:
                # uv run python scripts/attack_demo.py attack --speed 2
                source = _start_local_attack_demo()
            else:
                source = _make_source(
                    mode,
                    uploaded_file=uploaded_file,
                    replay_speed=float(replay_speed),
                    capture_interface=capture_interface,
                )
            live_artifacts = select_live_artifacts(
                mode=mode,
                attack_requested=attack_requested,
                loaded=loaded,
                baseline_run=baseline_run,
                reports_dir=REPORTS_DIR,
            )
            engine = LiveEngine(
                live_artifacts,
                source=source,
                # Short local windows make the first graph point appear quickly
                # while keeping scan, login, and bulk-transfer phases separate.
                window_seconds=(
                    15 if attack_requested and _local_attack_demo_available() else int(live_window)
                ),
                stride_seconds=(
                    5 if attack_requested and _local_attack_demo_available() else int(live_stride)
                ),
                history=120,
                threshold=float(live_threshold),
            )
            engine.start()
            st.session_state["live_engine"] = engine
            if attack_requested:
                st.success(
                    "Local attack scripts started at speed 2. Watch the event count, "
                    "completed windows, and stage change below."
                )
            else:
                st.toast("Live engine started")
        except Exception as error:  # noqa: BLE001 - surface the problem in the UI
            st.error(f"Failed to start: {error}")

    if stop_requested:
        engine = st.session_state.get("live_engine")
        if engine is not None:
            engine.stop()
        st.session_state.pop("live_engine", None)
        _stop_local_attack_demo()
        st.toast("Live engine stopped")

    if "live_engine" in st.session_state:
        _live_poll_fragment()

    if "live_engine" not in st.session_state:
        st.info(
            "Choose a source and press **Start**. Synthetic replay works in the "
            "hosted app; CSV and JSONL modes use the uploaded file directly. "
            "The original localhost terminal demo is not required here."
        )
