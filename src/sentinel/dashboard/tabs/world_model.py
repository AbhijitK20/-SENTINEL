# SPDX-License-Identifier: Apache-2.0
"""World Model tab — imagined futures, not just nowcasts.

Shows the three things a world model has to be able to answer:

1. what does it think happens next (the imagined probability timeline and the
   stage trajectory it predicts along the way),
2. what it is actually worth on states it had to imagine (open-loop error
   against the states that really happened, versus persistence), and
3. whether its explanation holds up (which features drive the risk logit).

It also accepts a PCAP or flow CSV, because the problem statement asks for a
demonstration interface that takes a file rather than a dataset.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import plotly.graph_objects as go
import streamlit as st

from sentinel.features import vectorize_states
from sentinel.file_forecast import forecast_from_file
from sentinel.predict import DECISION_THRESHOLD
from sentinel.world_model.imagine import (
    aggregate_open_loop,
    imagination_forecast,
    imagine,
    open_loop_error,
    risk_saliency,
)
from sentinel.world_model.train import WorldModelConfig, train_world_model

# Features shown side by side with their imagined future. Chosen because they
# are the observables an analyst recognises: scan fan-out, SYN+RST share,
# transfer volume, and the packet-level window size.
TRACKED_FEATURES = (
    "dst_port_nunique",
    "flag_syn_ratio",
    "bytes_sum",
    "tcp_window_size_mean",
    "retransmission_rate",
    "failed_auth_sum",
)


@st.cache_resource(show_spinner="Training the world model (RSSM)…")
def _train(labelled, manifest, schema, config, seed: int, sequence_length: int):
    return train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=config,
        seed=seed,
        sequence_length=sequence_length,
    )


def _state_series(states) -> dict[str, list[float]]:
    return {
        name: [float(state.features.get(name, 0.0)) for state in states]
        for name in TRACKED_FEATURES
        if any(name in state.features for state in states)
    }


def _open_loop_table(
    core, grouped, scenarios, schema, history: int, horizon: int, samples: int, seed: int
):
    """Measure open-loop error on held-out scenarios, the way the benchmark does."""
    errors = []
    for scenario_id in scenarios:
        states = [item.state for item in grouped[scenario_id]]
        for end in range(history, len(states) - horizon + 1):
            observed = states[end - history : end]
            future = states[end : end + horizon]
            errors.append(
                open_loop_error(
                    core,
                    vectorize_states(observed, schema),
                    vectorize_states(future, schema),
                    n_samples=samples,
                    seed=seed,
                )
            )
    return aggregate_open_loop(errors) if errors else None


def render(
    labelled: list,
    manifest: Any,
    schema: Any,
    *,
    loaded: Any = None,
    sequence_length: int = 8,
    forecast_horizon: int = 5,
    seed: int = 42,
    imagination_samples: int = 32,
) -> None:
    """Render the World Model tab."""
    st.subheader("World Model — imagined futures")
    st.caption(
        "Burns in on the observed history, then rolls the prior forward with no "
        "observations. Every probability below is a simulated future, not a "
        "measurement. Offline; runs from the trained model only."
    )

    if not st.checkbox("Train world model", value=False, key="wm_train"):
        st.info(
            "Tick **Train world model** to fit the RSSM on the current dataset. "
            "Training runs the open-loop objective, so it takes a little longer than "
            "the per-horizon GRU."
        )
        _render_upload(loaded)
        return

    config = WorldModelConfig(
        hidden_size=64,
        latent_dim=16,
        max_epochs=40,
        kl_anneal_epochs=8,
        rollout_steps=min(3, max(1, sequence_length - 1)),
    )
    run = _train(labelled, manifest, schema, config, int(seed), int(sequence_length))
    result = run.result

    cols = st.columns(5)
    cols[0].metric("Core", config.core_type)
    cols[1].metric("Best epoch", result.best_epoch)
    cols[2].metric("Observed features", result.observation_dim)
    cols[3].metric("Test recon MSE", f"{result.metrics['test'].reconstruction_mse:.4f}")
    cols[4].metric("Test stage macro-F1", f"{result.metrics['test'].stage_macro_f1:.3f}")

    grouped: dict[str, list] = {}
    for item in labelled:
        grouped.setdefault(item.scenario_id, []).append(item)
    for scenario_id in grouped:
        grouped[scenario_id] = sorted(
            grouped[scenario_id], key=lambda item: item.state.window_start
        )

    # ── 1. imagination from the current end of a scenario ────────────────
    test_scenarios = manifest.test_scenarios or sorted(grouped)
    scenario_id = st.selectbox("Scenario", test_scenarios, key="wm_scenario")
    states = [item.state for item in grouped[scenario_id]]
    history = min(int(sequence_length), len(states))
    cut = st.slider(
        "Observed history ends at window",
        min_value=history,
        max_value=len(states),
        value=len(states),
        key="wm_cut",
        help="Moving this earlier makes the model imagine a future it has not seen "
        "yet, so the timeline moves away from the observed trajectory.",
    )
    observed = states[max(0, cut - history) : cut]
    realized = states[cut : cut + forecast_horizon]

    threshold = st.slider(
        "Decision threshold", 0.05, 0.95, float(DECISION_THRESHOLD), 0.05, key="wm_threshold"
    )
    forecast, diagnostics = imagination_forecast(
        observed,
        run.core,
        schema,
        result.stage_vocabulary,
        max_horizon=forecast_horizon,
        threshold=float(threshold),
        n_samples=imagination_samples,
        seed=int(seed),
    )

    st.markdown("#### Imagined infiltration probability")
    figure = go.Figure()
    figure.add_trace(
        go.Scatter(
            x=[point.window for point in forecast.probability_timeline],
            y=[point.infiltration_probability for point in forecast.probability_timeline],
            name="P(infiltration) — imagined",
            mode="lines+markers",
            line={"color": "#6ea8ff"},
        )
    )
    if realized:
        figure.add_trace(
            go.Scatter(
                x=list(range(1, len(realized) + 1)),
                y=[1.0 if item.label.infiltration else 0.0 for item in realized],
                name="realized infiltration",
                mode="lines+markers",
                line={"color": "#f0c674", "dash": "dot"},
            )
        )
    figure.add_hline(y=float(threshold), line_dash="dash", line_color="#6dd3a8")
    figure.update_layout(
        template="plotly_dark",
        paper_bgcolor="#0b0d12",
        plot_bgcolor="#0b0d12",
        height=320,
        xaxis_title="windows ahead",
        yaxis_title="probability",
        yaxis_range=[0, 1],
        legend={"orientation": "h"},
    )
    st.plotly_chart(figure, use_container_width=True)
    st.caption(
        f"Predicted stage **{forecast.predicted_stage.name}** "
        f"(p={forecast.predicted_stage.probability:.2f}, "
        f"{forecast.predicted_stage.confidence} confidence). "
        f"Between-sample spread {diagnostics['risk_spread']:.3f}; "
        f"crossing rate across {int(diagnostics['samples'])} imagined futures "
        f"{diagnostics['crossing_rate']:.2f}."
    )

    if realized:
        st.markdown("#### What the model imagined vs what happened")
        matrix = vectorize_states(observed, schema)
        rollout = imagine(
            run.core, matrix, k=forecast_horizon, n_samples=imagination_samples, seed=int(seed)
        )
        imagined = rollout.observations.mean(dim=0).numpy()
        observed_series = _state_series(observed)
        realized_series = _state_series([item.state for item in realized])
        names = [name for name in TRACKED_FEATURES if name in observed_series]
        st.dataframe(
            {
                "feature": names,
                "observed now": [observed_series[name][-1] for name in names],
                "imagined mean": [
                    float(np.mean(imagined[:, schema.names.index(name)])) for name in names
                ],
                "realized": [realized_series.get(name, [None])[0] for name in names],
            },
            width="stretch",
        )
        st.caption(
            "Imagined values are in standardized feature space (0 = training mean); "
            "the observed and realized columns are raw. Use them to see direction, "
            "not magnitude."
        )

    # ── 2. is the simulation worth anything? ─────────────────────────────
    st.markdown("#### Open-loop skill on held-out scenarios")
    st.caption(
        "mean |imagined − realized| over standardized features, with no observations "
        "after the burn-in. Skill = 1 − model error / persistence error; positive "
        "means better than repeating the last window."
    )
    error = _open_loop_table(
        run.core,
        grouped,
        test_scenarios,
        schema,
        history,
        forecast_horizon,
        imagination_samples,
        int(seed),
    )
    if error is not None:
        figure = go.Figure()
        figure.add_trace(
            go.Bar(
                x=[f"+{step}" for step in error.steps],
                y=error.model_mae,
                name="world model",
                marker_color="#6ea8ff",
            )
        )
        figure.add_trace(
            go.Bar(
                x=[f"+{step}" for step in error.steps],
                y=error.persistence_mae,
                name="persistence",
                marker_color="#6dd3a8",
                opacity=0.6,
            )
        )
        figure.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0b0d12",
            plot_bgcolor="#0b0d12",
            height=300,
            barmode="group",
            yaxis_title="mean absolute error",
            legend={"orientation": "h"},
        )
        st.plotly_chart(figure, use_container_width=True)
        verdict = "beats" if error.mean_skill > 0 else "does not beat"
        st.caption(
            f"{error.windows} windows · mean skill **{error.mean_skill:+.3f}** — "
            f"the model {verdict} persistence. Open-loop error grows with horizon by "
            "construction."
        )

    # ── 3. explanation ───────────────────────────────────────────────────
    st.markdown("#### Driving features (gradient saliency)")
    drivers = risk_saliency(run.core, vectorize_states(observed, schema), schema.names)
    st.dataframe(
        {
            "feature": [d.name for d in drivers],
            "contribution": [d.contribution for d in drivers],
            "direction": [d.direction for d in drivers],
        },
        width="stretch",
    )
    st.caption(
        "First-order attribution of the risk logit at the newest observed window. "
        "Model evidence, not causation, and not SHAP."
    )

    _render_upload(loaded)


def _render_upload(loaded: Any) -> None:
    st.markdown("#### Run on your own telemetry")
    st.caption(
        "Drop a PCAP or a flow CSV. It is parsed locally, windowed, and scored by "
        "the same models — nothing leaves the machine."
    )
    upload = st.file_uploader("PCAP or flow CSV", type=["pcap", "pcapng", "csv"], key="wm_upload")
    if upload is None or loaded is None:
        return
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / upload.name
        path.write_bytes(upload.getvalue())
        try:
            result = forecast_from_file(
                path,
                loaded,
                forecaster="per_horizon",
                window_seconds=60,
                stride_seconds=30,
            )
        except (ValueError, FileNotFoundError) as error:
            st.error(f"Could not build windows from this file: {error}")
            return
    telemetry = result.telemetry
    st.write(
        f"`{telemetry.path}` — {telemetry.events} events → {telemetry.states} windows · "
        f"flow coverage {telemetry.flow_coverage} · packet coverage {telemetry.packet_coverage}"
    )
    st.dataframe(
        {
            "window": [p.window for p in result.forecast.probability_timeline],
            "P(infiltration)": [
                p.infiltration_probability for p in result.forecast.probability_timeline
            ],
            "confidence": [p.confidence for p in result.forecast.probability_timeline],
            "flagged": [
                p.window in result.flagged_windows for p in result.forecast.probability_timeline
            ],
        },
        width="stretch",
    )
    for warning in result.forecast.warnings:
        st.caption(f"⚠ {warning}")


__all__ = ["render"]
