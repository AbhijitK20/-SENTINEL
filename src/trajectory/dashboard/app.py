"""Trajectory Dashboard — offline interactive demo for SIH26153.

Run with:
    uv run streamlit run src/trajectory/dashboard/app.py

No cloud APIs required. All inference runs from saved local artifacts.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from trajectory.baseline import SPLIT_NAMES, train_baseline
from trajectory.config import BaselineConfig
from trajectory.evaluation import evaluate_replay
from trajectory.features import fit_feature_schema
from trajectory.predict import DECISION_THRESHOLD, artifacts_from_runs, forecast
from trajectory.report import render_report
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest
from trajectory.temporal import TemporalConfig, train_temporal

ROOT = Path(__file__).resolve().parent.parent.parent.parent
REPORTS_DIR = ROOT / "reports" / "generated"
DEFAULT_SCENARIOS = [f"scenario-{index:02d}" for index in range(1, 11)]

# ── Page Config ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="Trajectory — SIH26153",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar ───────────────────────────────────────────────────────────
with st.sidebar:
    st.title("Trajectory")
    st.caption("SIH26153 — AI Network Attack Forecasting")
    st.divider()
    st.subheader("Settings")
    scenario_count = st.slider("Scenarios", min_value=3, max_value=15, value=10)
    seed = st.number_input("Seed", min_value=0, max_value=9999, value=42)
    window_seconds = st.number_input("Window (s)", min_value=10, max_value=300, value=60)
    stride_seconds = st.number_input("Stride (s)", min_value=5, max_value=300, value=30)
    sequence_length = st.number_input("Sequence length", min_value=2, max_value=16, value=8)
    forecast_horizon = st.number_input("Forecast horizon", min_value=1, max_value=10, value=5)
    st.divider()
    st.subheader("Models")
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
        sequence_length=8,
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
):
    config = BaselineConfig()
    baseline_run = train_baseline(labelled, samples, manifest, config=config, seed=seed)

    train_states = [item.state for item in labelled if item.scenario_id in manifest.train_scenarios]
    schema = fit_feature_schema(
        train_states,
        excluded_features=config.excluded_features,
    )

    temporal_config = TemporalConfig(
        hidden_size=32,
        num_layers=1,
        max_epochs=50,
        early_stopping_patience=8,
    )
    temporal_run = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=schema,
        config=temporal_config,
        seed=seed,
        max_horizon=min(forecast_horizon, 5),
    )
    return baseline_run, temporal_run, schema


# ── Main ──────────────────────────────────────────────────────────────
st.title("🛡️ Trajectory — Network Attack Forecasting Dashboard")

# Generate data
labelled, samples, manifest = generate_data(scenario_count, seed, window_seconds, stride_seconds)

# Train on button click
if train_btn:
    with st.spinner("Training baseline + temporal model..."):
        baseline_run, temporal_run, schema = train_models(labelled, samples, manifest, seed)
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
tab_overview, tab_forecast, tab_states, tab_compare, tab_replay, tab_demo, tab_metrics = st.tabs(
    ["Overview", "Forecast", "Network States", "Comparison", "Replay", "Demo", "Metrics"]
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
    scenario_choice = st.selectbox(
        "Select scenario for forecast",
        manifest.test_scenarios or manifest.validation_scenarios,
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
            if row.scenario_id
            == st.selectbox(
                "Scenario",
                sorted({s.scenario_id for s in replay_eval.summaries}),
                key="replay_row_scenario",
            )
        ]
        st.dataframe(rows_data, use_container_width=True, hide_index=True)

        report_md = render_report(
            forecast(
                [i.state for i in labelled if i.scenario_id == rows_data[0]["scenario"]],
                loaded,
                max_horizon=forecast_horizon,
            ),
            scenario_id=rows_data[0]["scenario"],
            evaluation=replay_eval,
        )
        st.download_button(
            "Download analyst report (Markdown)",
            data=report_md,
            file_name="forecast_report.md",
            mime="text/markdown",
        )

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
