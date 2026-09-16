"""SENTINEL Dashboard — offline interactive demo for SIH26153.

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

from trajectory.baseline import train_baseline
from trajectory.case_studies import (
    dubsmash_inspired_case,
    packet_flow_steps,
    replay_topology,
)
from trajectory.cic_ids2017 import build_labelled_states, load_flow_csv
from trajectory.config import BaselineConfig
from trajectory.dashboard.network_graphs import kill_chain_figure, topology_figure
from trajectory.dashboard.state import LEDGER_PATH
from trajectory.dashboard.tabs import live as _live_tab
from trajectory.evaluation import evaluate_replay
from trajectory.features import fit_feature_schema
from trajectory.ledger import AlertLedger
from trajectory.predict import DECISION_THRESHOLD, artifacts_from_runs, forecast
from trajectory.report import render_report
from trajectory.schemas import SPLIT_NAMES
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import (
    build_sequence_samples,
    make_split_manifest,
    make_stratified_split_manifest,
)
from trajectory.temporal import TemporalConfig, train_temporal

ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _scenario_ids(count: int) -> list[str]:
    """Scenario ids for a requested count — never silently truncated."""
    if count < 1:
        raise ValueError("at least one scenario is required")
    return [f"scenario-{index:02d}" for index in range(1, count + 1)]


# ── Page Config ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="SENTINEL — SIH26153",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar ───────────────────────────────────────────────────────────
CIC_DATA_DIR = ROOT / "data" / "raw" / "cic-ids2017" / "TrafficLabelling"

# Stage precedence used to pick each scenario's dominant attack class.
_STAGE_RANK = {
    "Benign": 0,
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Credential Access": 3,
    "Command and Control": 4,
    "Denial of Service": 5,
    "Lateral Movement": 6,
}

# One entry per real CIC-IDS2017 attack day: file stem, short attack name,
# and the working-hours window that actually contains that day's traffic.
# NOTE: the Friday afternoon files' published timestamps run late
# (e.g. DDoS flows span 15:30-17:02), so their windows are set from the
# observed data, not the nominal capture schedule.
CIC_DAYS: list[tuple[str, str, tuple[int, int]]] = [
    ("Tuesday-WorkingHours", "FTP/SSH brute force", (8, 18)),
    ("Wednesday-workingHours", "DoS (4 variants + Heartbleed)", (8, 18)),
    ("Thursday-WorkingHours-Morning-WebAttacks", "Web attacks (XSS/SQLi/Brute)", (8, 14)),
    ("Thursday-WorkingHours-Afternoon-Infilteration", "Infiltration", (13, 17)),
    ("Friday-WorkingHours-Morning", "Botnet C2", (8, 13)),
    ("Friday-WorkingHours-Afternoon-PortScan", "Port scan", (13, 17)),
    ("Friday-WorkingHours-Afternoon-DDos", "DDoS", (15, 18)),
]


def _cic_csv(stem: str) -> Path | None:
    matches = sorted(CIC_DATA_DIR.glob(f"{stem}*.csv"))
    return matches[0] if matches else None


with st.sidebar:
    st.title("SENTINEL")
    st.caption("SIH26153 — AI Network Attack Forecasting")
    st.divider()
    st.subheader("Data Source")
    available_days = [(stem, label) for stem, label, _ in CIC_DAYS if _cic_csv(stem) is not None]
    data_mode = st.radio(
        "Training data",
        ("Synthetic replay", "Real CIC-IDS2017 attacks"),
        help="Synthetic: deterministic recon→lateral replays. Real: labeled "
        "attack-day flows from the CIC-IDS2017 dataset (already downloaded).",
    )
    selected_cic_days: list[str] = []
    if data_mode == "Real CIC-IDS2017 attacks":
        if not available_days:
            st.warning("CIC-IDS2017 CSVs not found under data/raw; falling back to synthetic.")
            data_mode = "Synthetic replay"
        else:
            day_labels = {stem: label for stem, label in available_days}
            selected_cic_days = st.multiselect(
                "Attack days to train on",
                list(day_labels),
                default=list(day_labels),
                format_func=lambda s: f"{s.replace('-WorkingHours', '')} · {day_labels[s]}",
                help="Different days carry different attack techniques — "
                "retraining on a different subset yields a genuinely different model. "
                "Pick at least 3 days so every split can hold an attack class.",
            )
            if not selected_cic_days:
                st.warning("Select at least one attack day (or switch back to synthetic).")
    st.divider()
    st.subheader("Settings")
    scenario_count = st.slider("Scenarios", min_value=3, max_value=15, value=6)
    seed = st.number_input("Seed", min_value=0, max_value=9999, value=42)
    if data_mode == "Synthetic replay":
        window_seconds = st.number_input("Window (s)", min_value=10, max_value=300, value=60)
        stride_seconds = st.number_input("Stride (s)", min_value=5, max_value=300, value=30)
    else:
        # Real capture days: 5-minute CICFlowMeter-style windows match the
        # benchmark protocol (run_real_benchmark.py uses 300/150).
        window_seconds = st.number_input("Window (s)", min_value=60, max_value=600, value=300)
        stride_seconds = st.number_input("Stride (s)", min_value=30, max_value=600, value=150)
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
    scenario_ids = _scenario_ids(scenario_count)
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


@st.cache_data(show_spinner="Loading real CIC-IDS2017 attack days...")
def load_real_data(
    day_stems: tuple[str, ...],
    seed: int,
    window_seconds: int,
    stride_seconds: int,
    sequence_length: int,
    forecast_horizon: int,
) -> tuple:
    """Real attack-day flows, sliced into per-half-day sub-scenarios.

    Each selected day is split into two consecutive time slices, each its own
    scenario id ``<day>-am`` / ``<day>-pm``. Scenario-level split assignment
    then guarantees no window of a training scenario ever leaks into
    validation or test — same discipline as the synthetic path. Different
    day subsets + seeds produce genuinely different datasets and models.
    """
    from datetime import UTC, datetime

    # CIC days run Jul 4 (Tue) .. Jul 7 (Fri, 2017); map each file to its date.
    day_of_month = {
        "Tuesday-WorkingHours": 4,
        "Wednesday-workingHours": 5,
        "Thursday-WorkingHours-Morning-WebAttacks": 6,
        "Thursday-WorkingHours-Afternoon-Infilteration": 6,
        "Friday-WorkingHours-Morning": 7,
        "Friday-WorkingHours-Afternoon-PortScan": 7,
        "Friday-WorkingHours-Afternoon-DDos": 7,
    }

    labelled: list = []
    for stem in day_stems:
        csv_path = _cic_csv(stem)
        if csv_path is None:
            continue
        hours = next(h for s, _, h in CIC_DAYS if s == stem)
        span = hours[1] - hours[0]
        mid = hours[0] + span // 2
        date = day_of_month.get(stem, 4)
        for part, (start_h, end_h) in (("am", (hours[0], mid)), ("pm", (mid, hours[1]))):
            start = datetime(2017, 7, date, start_h, tzinfo=UTC)
            end = datetime(2017, 7, date, end_h, tzinfo=UTC)
            events = load_flow_csv(
                csv_path,
                scenario_id=f"{stem}-{part}",
                time_window=(start, end),
            )
            if not events:
                continue
            flow_labels = [(e.timestamp, e.provenance.rsplit(":", 1)[1]) for e in events]
            slice_states = build_labelled_states(
                events,
                flow_labels,
                window_seconds=window_seconds,
                stride_seconds=stride_seconds,
                scenario_id=f"{stem}-{part}",
            )
            # Keep only slices that carry attack traffic (any non-benign stage
            # or infiltration flag): an all-benign half-day would poison the
            # split (train_baseline refuses single-class training splits).
            if not any(
                item.label.infiltration or item.label.attack_stage != "Benign"
                for item in slice_states
            ):
                continue
            labelled.extend(slice_states)
    if not labelled:
        raise ValueError("no real flows loaded; check the CIC data directory")
    scenario_ids = sorted({item.scenario_id for item in labelled})
    samples = build_sequence_samples(
        labelled,
        sequence_length=sequence_length,
        horizon=forecast_horizon,
    )
    # Stratify the split by attack class so training never lands single-class
    # (e.g. all PortScan scenarios in train with zero infiltration targets).
    stage_by_scenario: dict[str, str] = {}
    for item in labelled:
        stage_by_scenario.setdefault(item.scenario_id, "Benign")
        if item.label.infiltration or (
            item.label.attack_stage != "Benign"
            and _STAGE_RANK.get(item.label.attack_stage, 0)
            > _STAGE_RANK.get(stage_by_scenario[item.scenario_id], 0)
        ):
            stage_by_scenario[item.scenario_id] = item.label.attack_stage
    manifest = make_stratified_split_manifest(scenario_ids, stage_by_scenario, seed=seed)
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

# Generate data (mode-dependent; different day subsets/seeds => different data)
if data_mode == "Real CIC-IDS2017 attacks" and selected_cic_days:
    labelled, samples, manifest = load_real_data(
        tuple(sorted(selected_cic_days)),
        int(seed),
        int(window_seconds),
        int(stride_seconds),
        int(sequence_length),
        int(forecast_horizon),
    )
    dataset_id = "CIC-IDS2017 (TrafficLabelling, attack days)"
else:
    labelled, samples, manifest = generate_data(
        scenario_count,
        int(seed),
        int(window_seconds),
        int(stride_seconds),
        int(sequence_length),
        int(forecast_horizon),
    )
    dataset_id = "synthetic-recon-lateral-v2"

# Invalidate stale trained models when the underlying dataset changes:
# the hash covers the mode, day subset, seed, and windowing, so switching
# any of them forces a retrain rather than scoring new data with an old model.
dataset_fingerprint = (
    f"{dataset_id}|{sorted(selected_cic_days)}|{seed}|{window_seconds}|{stride_seconds}|"
    f"{sequence_length}|{forecast_horizon}|{scenario_count}|{full_training}"
)
if st.session_state.get("dataset_fingerprint") != dataset_fingerprint:
    for stale in ("baseline_run", "temporal_run", "schema", "replay_eval"):
        st.session_state.pop(stale, None)
    st.session_state["dataset_fingerprint"] = dataset_fingerprint

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
(
    tab_overview,
    tab_forecast,
    tab_states,
    tab_compare,
    tab_replay,
    tab_demo,
    tab_live,
    tab_metrics,
    tab_story,
) = st.tabs(
    [
        "Overview",
        "Forecast",
        "Network States",
        "Comparison",
        "Replay",
        "Demo",
        "Live Detection",
        "Metrics",
        "Attack Story",
    ]
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

    # Walk-forward position: the forecast is made FROM this window, using
    # only the history up to it (honest simulation of "what would we have
    # known at this moment"). Moving the slider changes the model input,
    # the timeline, stage, evidence, and lead time — every value below is
    # derived from the selected cut, never a static render.
    max_cut = len(scenario_states)
    cut = st.slider(
        "Forecast from window",
        min_value=1,
        max_value=max_cut,
        value=max_cut,
        help="History length the forecaster sees. Drag left to replay earlier "
        "moments of the attack progression; the forecast updates for each.",
    )
    observed_window = scenario_states[cut - 1]
    st.caption(
        f"Observed window: **{observed_window.window_start:%H:%M:%S} → "
        f"{observed_window.window_end:%H:%M:%S}** · {cut} of {max_cut} windows "
        "of history visible to the model."
    )

    result = forecast(
        scenario_states[:cut],
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

    # Walk-forward history: score every prior position of this scenario with
    # the same model so the slider position maps onto a visible trajectory —
    # the "what the model would have said here" curve.
    st.subheader("Model Score Across This Scenario (walk-forward)")
    with st.spinner("Scoring prior windows..."):
        history_scores = []
        schema_ref = baseline_run.result.feature_schema
        from trajectory.features import vectorize_states as _vec  # local import: UI-only

        for pos in range(1, len(scenario_states) + 1):
            window_state = scenario_states[pos - 1]
            vector = _vec([window_state], schema_ref)
            proba = float(baseline_run.model.predict_proba(vector)[:, 1][0])
            history_scores.append((pos, proba))
    fig_hist = go.Figure()
    fig_hist.add_trace(
        go.Scatter(
            x=[pos for pos, _ in history_scores],
            y=[p for _, p in history_scores],
            mode="lines+markers",
            name="P(infiltration) per window",
            line=dict(color="#6ea8ff", width=2),
        )
    )
    fig_hist.add_vline(
        x=cut,
        line_dash="dot",
        line_color="#ef6f6f",
        annotation_text="current cut",
    )
    fig_hist.add_hline(
        y=DECISION_THRESHOLD,
        line_dash="dash",
        line_color="#f0c674",
        annotation_text=f"Threshold = {DECISION_THRESHOLD}",
    )
    fig_hist.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=280,
        xaxis_title="Window position in scenario",
        yaxis_title="Probability",
        yaxis_range=[0, 1.05],
    )
    st.plotly_chart(fig_hist, use_container_width=True)

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
        "State index",
        min_value=0,
        max_value=len(scenario_states) - 1,
        value=min(cut - 1, len(scenario_states) - 1) if scenario_states else 0,
        help="Inspect any window: features, entities, edges, and the model's "
        "score for exactly this state. Every index change re-renders all "
        "charts below from that window's data.",
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
                "edge_count": len(state.edge_summary),
            }
        )
    with col2:
        st.json(
            {
                "coverage": state.coverage,
                "label": next(
                    (
                        item.label.attack_stage
                        for item in labelled
                        if item.scenario_id == scenario_choice
                        and item.state.window_start == state.window_start
                    ),
                    None,
                ),
            }
        )

    # Model score for THIS state, so the window inspection connects to the
    # forecast story (same model, same feature schema).
    from trajectory.features import vectorize_states as _vec_states  # UI-only

    state_vector = _vec_states([state], baseline_run.result.feature_schema)
    state_proba = float(baseline_run.model.predict_proba(state_vector)[:, 1][0])
    m1, m2, m3 = st.columns(3)
    m1.metric("Events in window", f"{state.features.get('event_count', 0):.0f}")
    m2.metric("Bytes in window", f"{state.features.get('bytes', 0):,.0f}")
    m3.metric("Model P(infiltration)", f"{state_proba:.1%}")

    st.subheader("Feature Values (log scale)")
    feat_names = list(state.features.keys())
    feat_vals = list(state.features.values())
    fig5 = go.Figure(
        data=[
            go.Bar(
                x=feat_names,
                y=[max(v, 0.0) for v in feat_vals],
                marker_color="#6ea8ff",
                text=[f"{v:,.3g}" for v in feat_vals],
                textposition="outside",
            )
        ]
    )
    # Log scale: real windows mix bytes (~1e5) with flag counts (~1e1) — a
    # linear axis flattened every feature but bytes into identical zero-bars.
    fig5.update_yaxes(type="log")
    fig5.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=340,
        xaxis_tickangle=-45,
    )
    st.plotly_chart(fig5, use_container_width=True)

    # Per-window feature evolution for the features that change most across
    # the scenario — moving the slider above visibly moves the marker.
    st.subheader("Selected Window in Scenario Evolution")
    evolution_names = [
        name
        for name in ("event_count", "bytes", "syn_count", "rst_count", "flow_event_count")
        if any(name in s.features for s in scenario_states)
    ]
    fig_evo = go.Figure()
    for name in evolution_names:
        fig_evo.add_trace(
            go.Scatter(
                x=[s.window_start.isoformat() for s in scenario_states],
                y=[s.features.get(name, 0.0) for s in scenario_states],
                mode="lines",
                name=name,
            )
        )
    if evolution_names:
        fig_evo.add_vline(
            x=state.window_start.isoformat(),
            line_dash="dot",
            line_color="#ef6f6f",
            annotation_text="selected window",
        )
    fig_evo.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=300,
        xaxis_title="Window start",
        yaxis_title="Value (log)",
    )
    fig_evo.update_yaxes(type="log")
    st.plotly_chart(fig_evo, use_container_width=True)

    # Edge table for the selected window — the raw host-to-host activity.
    with st.expander(f"Edges in selected window ({len(state.edge_summary)})"):
        if state.edge_summary:
            st.dataframe(
                [
                    {
                        "source": e["source"],
                        "destination": e["destination"],
                        "flows": e["count"],
                        "bytes": e["bytes"],
                    }
                    for e in state.edge_summary[:50]
                ],
                use_container_width=True,
            )
        else:
            st.caption("No edges in this window.")

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

    replay_signature = (
        dataset_fingerprint,
        int(forecast_horizon),
        "test",
        8,
    )
    if st.session_state.get("replay_signature") != replay_signature:
        st.session_state.pop("replay_eval", None)
        st.session_state["replay_signature"] = replay_signature

    replay_control_col, replay_clear_col = st.columns([3, 1])
    run_replay = replay_control_col.button(
        "Run replay evaluation",
        key="run-replay-evaluation",
        type="primary",
    )
    clear_replay = replay_clear_col.button("Clear result", key="clear-replay-evaluation")
    if clear_replay:
        st.session_state.pop("replay_eval", None)
        st.info(
            "Replay result cleared. Run the evaluation again for the current model and dataset."
        )
    if run_replay:
        with st.spinner("Walking forward through scenarios..."):
            try:
                st.session_state["replay_eval"] = evaluate_replay(
                    labelled,
                    loaded,
                    horizon=forecast_horizon,
                    split_filter="test",
                    max_history=8,
                )
            except ValueError as error:
                st.session_state.pop("replay_eval", None)
                st.error(f"Replay could not run: {error}")

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
    if not demo_scenarios:
        st.warning("No validation or test scenarios are available for the guided demo.")
        st.stop()
    demo_scenario = st.selectbox("Replay scenario", demo_scenarios, key="demo_scenario")
    demo_labelled = [item for item in labelled if item.scenario_id == demo_scenario]
    demo_states = [item.state for item in demo_labelled]
    if not demo_states:
        st.warning("The selected scenario has no network states.")
        st.stop()

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
    state_count = len(demo_states)
    baseline_cut = min(max(1, state_count // 3), state_count)
    recon_cut = min(max(baseline_cut, state_count // 2), state_count)
    reality_index = min(baseline_cut, state_count - 1)
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
            f"{realized_stages[reality_index]} → {realized_stages[-1]} over the "
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


# ── Tab: Attack Story ────────────────────────────────────────────────
with tab_story:
    st.subheader("Dubsmash-Inspired Credential Reuse Breach")
    st.caption(
        "Educational workflow based on publicly reported breach impact. "
        "The technical path below is synthetic and bounded; it does not claim "
        "to reproduce undocumented Dubsmash internals or use real personal data."
    )

    story_col1, story_col2, story_col3 = st.columns(3)
    story_col1.metric("Reported impact", "~161–162M accounts")
    story_col2.metric("Demo records", "Synthetic sample")
    story_col3.metric("Primary pattern", "Credential reuse")

    phases = dubsmash_inspired_case()
    if "story_phase" not in st.session_state:
        st.session_state["story_phase"] = 1
    if "story_contained" not in st.session_state:
        st.session_state["story_contained"] = False

    st.subheader("Replay Controls")
    control_a, control_b, control_c, control_d = st.columns(4)
    if control_a.button("◀ Previous", key="story-previous"):
        st.session_state["story_phase"] = max(1, st.session_state["story_phase"] - 1)
    if control_b.button("Next ▶", key="story-next"):
        st.session_state["story_phase"] = min(len(phases), st.session_state["story_phase"] + 1)
    if control_c.button("↺ Reset Story", key="story-reset"):
        st.session_state["story_phase"] = 1
        st.session_state["story_contained"] = False
    if control_d.button("⛊ Contain at Firewall", key="story-contain"):
        st.session_state["story_contained"] = True

    current_phase = st.session_state["story_phase"]
    phase = phases[current_phase - 1]
    st.progress(
        current_phase / len(phases),
        text=f"Phase {current_phase}/{len(phases)} · {phase.name}",
    )
    if st.session_state["story_contained"]:
        st.success("Containment simulated: the attacker branch is blocked at the edge firewall.")
    else:
        st.warning("Demo mode: no defensive control is active yet.")

    st.subheader("1. Network Topology")
    nodes, edges = replay_topology(current_phase, contained=st.session_state["story_contained"])
    st.plotly_chart(
        topology_figure(nodes, edges, active_labels={phase.name}),
        use_container_width=True,
    )
    st.caption(
        "Nodes are hosts/services. Links represent observed communication, "
        "not proof of compromise. "
        "Blue is infrastructure, amber is suspicious, and red is malicious or contained demo "
        "traffic."
    )

    st.subheader("2. Attack Workflow")
    phase_cols = st.columns(len(phases))
    for column, phase in zip(phase_cols, phases, strict=True):
        with column:
            st.markdown(f"**{phase.number}. {phase.name}**")
            st.caption(phase.summary)
            st.markdown(f"`{phase.source}` → `{phase.destination}`")
            st.markdown(f"`{phase.protocol}:{phase.port}` · {phase.status}")
            for evidence in phase.evidence:
                st.markdown(f"- {evidence}")

    st.subheader("3. Packet and Application Flow")
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
        use_container_width=True,
        hide_index=True,
    )
    st.info(
        "Computer Networks distinction: TCP carries packets between hosts; HTTP describes the "
        "application request; database queries happen on a private service link. SENTINEL combines "
        "flow, web, authentication, and database-adjacent telemetry to form an incident."
    )

    st.subheader("4. Attack Kill Chain")
    active_types = {phase.attack_type for phase in phases[:current_phase]}
    from trajectory.sequence_detector import ATTACK_TRANSITIONS

    st.plotly_chart(
        kill_chain_figure(ATTACK_TRANSITIONS, active=active_types),
        use_container_width=True,
    )
    st.caption(
        "Transition weights are educational priors used for next-technique prediction; they are "
        "not claims about the historical Dubsmash incident."
    )

    st.subheader("5. Admin Response Workflow")
    response_steps = [
        ("Detect", "Detector finding and alert timeline", "Live Detection"),
        ("Triage", "Review source, asset, confidence, and evidence", "Incident panel"),
        ("Investigate", "Inspect topology, packet flow, and application logs", "Network States"),
        ("Contain", "Block the observed attacker or rate-limit the endpoint", "Admin blocklist"),
        ("Recover", "Revoke sessions, rotate credentials, preserve evidence", "Analyst-approved"),
        ("Review", "Document the case and monitor for recurrence", "Case record"),
    ]
    for index, (name, action, control) in enumerate(response_steps, start=1):
        left, middle, right = st.columns([1, 3, 2])
        left.markdown(f"**{index}. {name}**")
        middle.write(action)
        right.caption(control)

    st.warning(
        "Reset Demo Session clears in-memory findings for this demonstration. It does not repair "
        "a real system, erase forensic evidence, or replace credential rotation and session "
        "revocation."
    )

    st.subheader("6. Defense Comparison")
    before_col, after_col = st.columns(2)
    with before_col:
        st.markdown("**Without controls**")
        st.metric("Attack phases reached", current_phase)
        st.metric("Sensitive data path", "Available" if current_phase >= 4 else "Not reached")
        st.caption("The synthetic attacker can continue along the visible path.")
    with after_col:
        st.markdown("**With firewall containment**")
        contained_phase = (
            min(current_phase, 2) if st.session_state["story_contained"] else current_phase
        )
        st.metric("Attack phases reached", contained_phase)
        st.metric(
            "Sensitive data path",
            "Blocked" if st.session_state["story_contained"] else "Available",
        )
        st.caption(
            "Containment is simulated and analyst-approved; it does not alter host firewalls."
        )


# ── Tab: Live Detection (extracted to tabs/live.py) ──────────────────
with tab_live:
    _live_tab.render(
        seed=int(seed),
        loaded=loaded,
        baseline_run=baseline_run,
    )
