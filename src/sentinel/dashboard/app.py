"""SENTINEL — offline analyst console for network attack forecasting.

    uv run streamlit run src/sentinel/dashboard/app.py

No cloud API is used. All inference runs from artifacts built on this machine.

The shell owns three things and nothing else: the theme, the data and model
lifecycle, and routing. Every screen lives in :mod:`sentinel.dashboard.screens`
and renders through :mod:`sentinel.frontend`, so a screen can never invent a
colour or a radius.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import streamlit as st

from sentinel.baseline import train_baseline
from sentinel.cic_ids2017 import build_labelled_states, load_flow_csv
from sentinel.config import BaselineConfig
from sentinel.dashboard.screens import SCREENS, ScreenContext
from sentinel.dashboard.tabs import live as live_tab
from sentinel.dashboard.tabs import world_model as world_model_tab
from sentinel.frontend import ui
from sentinel.frontend.theme import apply_theme
from sentinel.predict import artifacts_from_runs
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import (
    build_sequence_samples,
    make_split_manifest,
    make_stratified_split_manifest,
)
from sentinel.temporal import TemporalConfig, train_temporal

ROOT = Path(__file__).resolve().parents[3]
SCENARIO_COUNT_DEFAULT = 6
TRAINABLE_HORIZONS = 5

apply_theme("SENTINEL — attack forecasting")

# ── Data source ─────────────────────────────────────────────────────────

# (csv stem, human label, (start hour, end hour)) for the CIC-IDS2017 attack
# days. One table, so the picker, the time slicing, and the labels agree.
CIC_DAYS: list[tuple[str, str, tuple[int, int]]] = [
    ("Tuesday-WorkingHours", "FTP/SSH brute force", (8, 18)),
    ("Wednesday-workingHours", "DoS + Heartbleed", (8, 18)),
    ("Thursday-WorkingHours-Morning-WebAttacks", "Web attacks (XSS/SQLi/Brute)", (8, 14)),
    ("Thursday-WorkingHours-Afternoon-Infilteration", "Infiltration", (13, 17)),
    ("Friday-WorkingHours-Morning", "Botnet C2", (8, 13)),
    ("Friday-WorkingHours-Afternoon-PortScan", "Port scan", (13, 17)),
    ("Friday-WorkingHours-Afternoon-DDos", "DDoS", (15, 18)),
]
CIC_DAY_OF_MONTH = {"Tuesday": 4, "Wednesday": 5, "Thursday": 6, "Friday": 7}
CIC_DATA_DIR = ROOT / "data" / "raw" / "cic-ids2017" / "TrafficLabelling"


def _cic_csv(stem: str) -> Path | None:
    matches = sorted(CIC_DATA_DIR.glob(f"{stem}*.csv"))
    return matches[0] if matches else None


def _available_days() -> list[tuple[str, str]]:
    return [(stem, label) for stem, label, _ in CIC_DAYS if _cic_csv(stem) is not None]


def _scenario_ids(count: int) -> list[str]:
    """Exactly ``count`` scenario ids. Never a fixed-length list.

    A hard-coded list silently capped every run at its length while the slider
    still offered more, so the count always comes from the caller.
    """
    if count < 1:
        raise ValueError("at least one scenario is required")
    return [f"scenario-{index:02d}" for index in range(1, count + 1)]


@st.cache_data(show_spinner="Building synthetic replay scenarios…")
def synthetic_dataset(
    scenario_count: int,
    seed: int,
    window_seconds: int,
    stride_seconds: int,
    sequence_length: int,
    forecast_horizon: int,
):
    scenario_ids = _scenario_ids(scenario_count)
    labelled = generate_labelled_states(
        scenario_ids,
        seed=seed,
        window_seconds=window_seconds,
        stride_seconds=stride_seconds,
    )
    samples = build_sequence_samples(
        labelled, sequence_length=sequence_length, horizon=forecast_horizon
    )
    return (
        labelled,
        samples,
        make_split_manifest(scenario_ids, seed=seed),
        "synthetic-recon-lateral-v2",
    )


@st.cache_data(show_spinner="Loading CIC-IDS2017 attack days…")
def cic_dataset(
    day_stems: tuple[str, ...],
    seed: int,
    window_seconds: int,
    stride_seconds: int,
    sequence_length: int,
    forecast_horizon: int,
):
    """Real attack-day flows, sliced into per-half-day scenarios.

    Each selected day becomes two consecutive sub-scenarios, so scenario-level
    splitting still guarantees no window of a training scenario reaches
    validation or test.
    """
    from datetime import UTC, datetime

    day_of_month = CIC_DAY_OF_MONTH
    labelled: list = []
    for stem, _label, (start_hour, end_hour) in CIC_DAYS:
        if stem not in day_stems:
            continue
        csv_path = _cic_csv(stem)
        if csv_path is None:
            continue
        mid = (start_hour + end_hour) // 2
        day = day_of_month.get(stem.split("-")[0], 4)
        for part, (lo, hi) in (("am", (start_hour, mid)), ("pm", (mid, end_hour))):
            events = load_flow_csv(
                csv_path,
                scenario_id=f"{stem}-{part}",
                time_window=(
                    datetime(2017, 7, day, lo, tzinfo=UTC),
                    datetime(2017, 7, day, hi, tzinfo=UTC),
                ),
            )
            if not events:
                continue
            labelled.extend(
                build_labelled_states(
                    events,
                    scenario_id=f"{stem}-{part}",
                    window_seconds=window_seconds,
                    stride_seconds=stride_seconds,
                )
            )
    if not labelled:
        raise ValueError("no CIC-IDS2017 windows could be built from the selected days")
    scenario_ids = sorted({item.scenario_id for item in labelled})
    stage_by_scenario = {
        scenario: next(
            (item.label.attack_stage for item in labelled if item.scenario_id == scenario),
            "Unknown",
        )
        for scenario in scenario_ids
    }
    samples = build_sequence_samples(
        labelled, sequence_length=sequence_length, horizon=forecast_horizon
    )
    manifest = make_stratified_split_manifest(scenario_ids, stage_by_scenario, seed=seed)
    return labelled, samples, manifest, "CIC-IDS2017 (attack days)"


@st.cache_resource(show_spinner="Training baseline + temporal models…")
def train_models(labelled, samples, manifest, seed, forecast_horizon, full_training):
    baseline_run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=0.5),
        seed=seed,
    )
    temporal_run = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=baseline_run.result.feature_schema,
        config=TemporalConfig(
            hidden_size=32,
            num_layers=1,
            max_epochs=100 if full_training else 40,
            early_stopping_patience=10,
        ),
        seed=seed,
        max_horizon=min(forecast_horizon, TRAINABLE_HORIZONS if full_training else 3),
    )
    return baseline_run, temporal_run


# ── Sidebar ─────────────────────────────────────────────────────────────

available = _available_days()
with st.sidebar:
    ui.header("SENTINEL", "analyst console")

    st.subheader("Data source")
    mode_options = ["Synthetic replay"] + (["CIC-IDS2017 attack days"] if available else [])
    mode = st.radio("Dataset", mode_options, index=0)

    selected_days: list[str] = []
    if mode == "CIC-IDS2017 attack days":
        selected_days = st.multiselect(
            "Attack days",
            [stem for stem, _ in available],
            default=[stem for stem, _ in available],
            format_func=lambda s: s.replace("-WorkingHours", ""),
            help="Different days carry different attack techniques. Pick at least "
            "three so every split can hold an attack class.",
        )
        if len(selected_days) < 3:
            st.warning("Select at least three attack days, or switch back to synthetic.")

    st.divider()
    st.subheader("Windows")
    scenario_count = st.slider(
        "Scenarios",
        3,
        15,
        SCENARIO_COUNT_DEFAULT,
        disabled=mode != "Synthetic replay",
        help="Scenarios are split whole into train/validation/test, so more "
        "scenarios means a larger holdout rather than longer training.",
    )
    seed = int(st.number_input("Seed", 0, 9999, 42))
    if mode == "Synthetic replay":
        window_seconds = int(st.number_input("Window (s)", 10, 300, 60))
        stride_seconds = int(st.number_input("Stride (s)", 5, 300, 30))
    else:
        window_seconds = int(st.number_input("Window (s)", 60, 600, 300))
        stride_seconds = int(st.number_input("Stride (s)", 30, 600, 150))
    sequence_length = int(st.number_input("Sequence length", 2, 16, 8))
    forecast_horizon = int(st.number_input("Forecast horizon", 1, 10, 5))

    st.divider()
    full_training = st.checkbox(
        "Full temporal training",
        value=False,
        help="Trains every horizon to convergence. Slower; needed only for the "
        "published benchmark numbers.",
    )
    train_clicked = st.button("Train / retrain", type="primary")

    st.divider()
    st.caption(f"Python {sys.version.split()[0]} · {platform.system()} · offline")

# ── Data ────────────────────────────────────────────────────────────────

use_real = mode == "CIC-IDS2017 attack days" and len(selected_days) >= 3
fingerprint = (
    f"{mode}|{sorted(selected_days)}|{seed}|{window_seconds}|{stride_seconds}|"
    f"{sequence_length}|{forecast_horizon}|{scenario_count}|{full_training}"
)
if st.session_state.get("fingerprint") != fingerprint:
    for stale in ("baseline_run", "temporal_run", "replay_eval"):
        st.session_state.pop(stale, None)
    st.session_state["fingerprint"] = fingerprint

try:
    if use_real:
        labelled, samples, manifest, dataset_id = cic_dataset(
            tuple(sorted(selected_days)),
            seed,
            window_seconds,
            stride_seconds,
            sequence_length,
            forecast_horizon,
        )
    else:
        labelled, samples, manifest, dataset_id = synthetic_dataset(
            scenario_count,
            seed,
            window_seconds,
            stride_seconds,
            sequence_length,
            forecast_horizon,
        )
except Exception as error:  # a bad dataset must not take the app down
    ui.header("SENTINEL", "analyst console")
    ui.banner(
        "Data source could not be read",
        f"{type(error).__name__}: {error}",
        tone="error",
        icon="✕",
    )
    st.stop()

# ── Models ──────────────────────────────────────────────────────────────

needs_training = "baseline_run" not in st.session_state
if train_clicked or needs_training:
    with st.spinner("Training models on this dataset…"):
        try:
            baseline_run, temporal_run = train_models(
                labelled,
                samples,
                manifest,
                seed,
                forecast_horizon,
                full_training,
            )
        except Exception as error:
            ui.header("SENTINEL", "analyst console")
            ui.banner(
                "Training failed",
                f"{type(error).__name__}: {error}. Try a lower sequence length, "
                "more scenarios, or a different seed.",
                tone="error",
                icon="✕",
            )
            st.stop()
    st.session_state["baseline_run"] = baseline_run
    st.session_state["temporal_run"] = temporal_run

baseline_run = st.session_state["baseline_run"]
temporal_run = st.session_state["temporal_run"]
loaded = artifacts_from_runs(baseline_run, temporal_run=temporal_run)

ctx = ScreenContext(
    labelled=labelled,
    samples=samples,
    manifest=manifest,
    baseline_run=baseline_run,
    temporal_run=temporal_run,
    loaded=loaded,
    dataset_id=dataset_id,
    dataset_fingerprint=fingerprint,
    forecast_horizon=forecast_horizon,
    window_seconds=window_seconds,
    stride_seconds=stride_seconds,
    sequence_length=sequence_length,
)

# ── Shell ───────────────────────────────────────────────────────────────

ui.header(
    "SENTINEL",
    "network attack forecasting",
    meta=(
        f"{dataset_id} · {len(labelled):,} windows · "
        f"{baseline_run.result.feature_schema.width} features · seed {seed}"
    ),
)

tabs = st.tabs(
    [
        "Overview",
        "Forecast",
        "World model",
        "Replay",
        "States",
        "Comparison",
        "Live",
        "Metrics",
        "Demo",
        "Attack story",
    ]
)

with tabs[0]:
    SCREENS["overview"](ctx)
with tabs[1]:
    SCREENS["forecast"](ctx)
with tabs[2]:
    world_model_tab.render(
        labelled=labelled,
        manifest=manifest,
        schema=baseline_run.result.feature_schema,
        loaded=loaded,
        sequence_length=sequence_length,
        forecast_horizon=forecast_horizon,
        seed=seed,
    )
with tabs[3]:
    SCREENS["replay"](ctx)
with tabs[4]:
    SCREENS["states"](ctx)
with tabs[5]:
    SCREENS["comparison"](ctx)
with tabs[6]:
    live_tab.render(seed=seed, loaded=loaded, baseline_run=baseline_run)
with tabs[7]:
    SCREENS["metrics"](ctx)
with tabs[8]:
    SCREENS["demo"](ctx)
with tabs[9]:
    SCREENS["story"](ctx)
