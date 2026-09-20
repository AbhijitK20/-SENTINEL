# SPDX-License-Identifier: Apache-2.0
"""Live Detection tab — streaming event scoring with attack trigger controls."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import plotly.graph_objects as go
import streamlit as st

from sentinel.assets import default_asset_registry
from sentinel.dashboard.live_artifacts import select_live_artifacts
from sentinel.feedback import VERDICTS as FEEDBACK_VERDICTS
from sentinel.feedback import FeedbackStore
from sentinel.live import (
    CsvReplaySource,
    EventReplaySource,
    JsonlSensorSource,
    LiveEngine,
    ScapyInterfaceSource,
    SyslogTailSource,
)
from sentinel.predict import DECISION_THRESHOLD
from sentinel.synthetic import generate_scenario_events

if TYPE_CHECKING:
    pass

ROOT = Path(__file__).resolve().parents[4]
REPORTS_DIR = ROOT / "reports" / "generated"
LOCAL_ATTACK_SPEED = 2.0


@st.fragment(run_every=2.0)
def _live_poll_fragment() -> None:
    """Auto-refreshing live status: polls the engine and redraws."""
    engine = st.session_state.get("live_engine")
    if engine is None:
        return
    _render_live_status(engine.poll())


def _render_live_status(status: Any) -> None:
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

        if latest.attack_findings:
            st.subheader("Attack-type risk grid")
            by_type = {f.attack_type: f for f in latest.attack_findings}
            grid_labels = [
                ("ddos", "DDoS"),
                ("reconnaissance", "Recon"),
                ("credential_abuse", "Credential"),
                ("lateral_movement", "Lateral"),
                ("command_and_control", "C2"),
                ("exfiltration", "Exfil"),
            ]
            grid_cols = st.columns(len(grid_labels))
            for col, (attack_type, label) in zip(grid_cols, grid_labels, strict=True):
                finding = by_type.get(attack_type)
                col.markdown(f"**{label}")
                if finding is None:
                    col.markdown("—")
                    continue
                if finding.is_alert:
                    tone = "red"
                elif finding.probability >= 0.40:
                    tone = "orange"
                else:
                    tone = "green"
                col.markdown(f":{tone}[**{finding.probability:.2f}**]")
                col.caption(f"{finding.severity} · {finding.mitre_technique}")
            c2 = by_type.get("command_and_control")
            if c2 is not None and c2.warnings:
                st.caption(f"ℹ️ {c2.warnings[0]}")
            # Summary when no detectors fire
            alert_count = sum(1 for f in latest.attack_findings if f.is_alert)
            if alert_count == 0:
                st.info(
                    "All detectors below threshold on this window. This is normal "
                    "during benign traffic. Detector scores are rule-based per-window "
                    "associations — they are different from the ML forecast shown in "
                    "the Forecast tab."
                )
            else:
                st.caption(
                    f"{alert_count} detector(s) fired on this window. Scores are "
                    "rule-based per-window associations, not proof. Alerts feed "
                    "the incident panel below."
                )

        if status.incidents:
            st.subheader("Correlated incidents")
            for incident in reversed(status.incidents[-3:]):
                header = (
                    f"{incident.incident_id} · risk {incident.risk.level} "
                    f"({incident.risk.score:.2f})"
                )
                with st.expander(header, expanded=False):
                    st.markdown("**Likely progression:** " + " → ".join(incident.progression))
                    if incident.affected_assets:
                        st.markdown("**Assets in scope:** " + ", ".join(incident.affected_assets))
                        registry = default_asset_registry()
                        known = [
                            registry[asset]
                            for asset in incident.affected_assets
                            if asset in registry
                        ]
                        if known:
                            st.dataframe(
                                [
                                    {
                                        "asset": record.asset_id,
                                        "role": record.role,
                                        "owner": record.owner,
                                        "criticality": record.criticality,
                                        "zone": record.network_zone,
                                    }
                                    for record in known
                                ],
                                hide_index=True,
                            )
                    st.caption(
                        f"First seen {incident.first_seen:%H:%M:%S} · last seen "
                        f"{incident.last_seen:%H:%M:%S} · risk = {incident.risk.formula}"
                    )
                    if incident.recommended_actions:
                        st.markdown(
                            "**Recommended actions** (analyst-approved; never auto-executed):"
                        )
                        for action in incident.recommended_actions:
                            st.markdown(f"- {action}")
                    verdict = st.selectbox(
                        "Analyst verdict",
                        sorted(FEEDBACK_VERDICTS),
                        key=f"fb-verdict-{incident.incident_id}-{incident.last_seen}",
                    )
                    if st.button(
                        "Record feedback",
                        key=f"fb-record-{incident.incident_id}-{incident.last_seen}",
                    ):
                        FeedbackStore(ROOT / "reports" / "live" / "feedback.jsonl").record(
                            incident.incident_id,
                            verdict,
                            analyst="dashboard",
                        )
                        st.success(f"Recorded {verdict} for {incident.incident_id}.")

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
    uploaded_file: Any = None,
    replay_speed: float = 60.0,
    capture_interface: str = "lo",
    seed: int = 42,
) -> Any:
    """Build the event source selected in the Live tab."""
    if mode == "Synthetic attack replay":
        events, _ = generate_scenario_events("hosted-demo", seed=int(seed))
        return EventReplaySource(events, speed=replay_speed)
    if mode == "CSV replay":
        if uploaded_file is None:
            raise ValueError("Upload a CICFlowMeter CSV before starting the replay")
        handle = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        handle.write(uploaded_file.getvalue())
        handle.close()
        return CsvReplaySource(handle.name, speed=replay_speed)
    if mode == "Local loopback capture":
        return ScapyInterfaceSource(capture_interface.strip() or "lo")
    if mode == "Syslog log file":
        if uploaded_file is None:
            raise ValueError("Upload a syslog-format log file before starting the replay")
        handle = tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="wb")
        handle.write(uploaded_file.getvalue())
        handle.close()
        return SyslogTailSource(handle.name, scenario_id="uploaded-syslog", follow=False)
    if uploaded_file is None:
        raise ValueError("Upload a JSONL sensor file before starting the replay")
    handle = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="wb")
    handle.write(uploaded_file.getvalue())
    handle.close()
    return JsonlSensorSource(handle.name, scenario_id="uploaded-sensor", follow=False)


def _local_attack_demo_available() -> bool:
    """Return whether the app is running where the localhost demo can execute."""
    return not Path("/mount/src").exists()


def _start_local_attack_demo(seed: int = 42) -> JsonlSensorSource:
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


def render(seed: int = 42, loaded: Any = None, baseline_run: Any = None) -> None:
    """Render the Live Detection tab."""
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
            "Syslog log file",
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
    elif mode == "Syslog log file":
        uploaded_file = st.file_uploader(
            "Upload a syslog-format log file", type=["log", "txt"], key="live-syslog-upload"
        )
        st.caption(
            "Each line: `<ISO or epoch timestamp> <host> <app> k=v …` — known keys become "
            "detector features (e.g. failed_auth=yes, bytes, syn_count); other lines are skipped."
        )
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

    st.divider()
    st.subheader("Force Attack — Trigger Real Attack Scripts")
    target_url = os.environ.get("SENTINEL_DEMO_TARGET", "http://127.0.0.1:5000")
    st.caption(
        "Launch attack scripts against the vulnerable demo app "
        f"({target_url}). The scanner picks up the traffic and pushes "
        "it into the SENTINEL API so detectors fire on real HTTP requests."
    )
    st.caption(
        "These buttons run the actual attack modules (brute_force, sqli, scan) "
        "against the vulnerable Flask app. They require the demo stack to be "
        "running (docker compose --profile demo up or the vulnerable app locally)."
    )
    attack_col1, attack_col2, attack_col3 = st.columns(3)
    with attack_col1:
        if st.button("🔑 Brute Force Attack", key="attack-brute-force"):
            st.session_state["pending_attack"] = "brute_force"
    with attack_col2:
        if st.button("💉 SQL Injection Attack", key="attack-sqli"):
            st.session_state["pending_attack"] = "sqli"
    with attack_col3:
        if st.button("🔍 Port Scan Attack", key="attack-scan"):
            st.session_state["pending_attack"] = "scan"

    pending_attack = st.session_state.pop("pending_attack", None)
    if pending_attack:
        cmd_map = {
            "brute_force": [
                sys.executable,
                "-m",
                "apps.vulnerable.attacks.brute_force",
                "--target",
                target_url,
                "--delay",
                "0.1",
                "--attempts",
                "5",
            ],
            "sqli": [
                sys.executable,
                "-m",
                "apps.vulnerable.attacks.sqli",
                "--target",
                target_url,
                "--delay",
                "0.1",
                "--rounds",
                "1",
            ],
            "scan": [
                sys.executable,
                "-m",
                "apps.vulnerable.attacks.scan",
                "--target",
                target_url,
                "--delay",
                "0.05",
                "--rounds",
                "1",
            ],
        }
        attack_labels = {
            "brute_force": "Brute Force",
            "sqli": "SQL Injection",
            "scan": "Port Scan",
        }
        cmd = cmd_map[pending_attack]
        label = attack_labels[pending_attack]

        with st.spinner(f"Resetting live engine and running {label} attack..."):
            live_eng = st.session_state.get("live_engine")
            if live_eng is not None:
                live_eng.reset()

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    cwd=str(ROOT),
                )
                output = result.stdout + result.stderr
                if result.returncode == 0:
                    st.success(f"{label} attack completed successfully.")
                else:
                    st.warning(f"{label} attack finished with code {result.returncode}.")
                with st.expander(f"{label} output"):
                    st.code(output[:3000])
            except subprocess.TimeoutExpired:
                st.error(f"{label} attack timed out after 60s.")
            except Exception as exc:
                st.error(f"Failed to run {label} attack: {exc}")

    if start_requested or attack_requested:
        try:
            if attack_requested:
                if not _local_attack_demo_available():
                    raise RuntimeError(
                        "The local attack scripts can only run on the machine hosting "
                        "Streamlit. Run SENTINEL locally for this button."
                    )
                _stop_local_attack_demo()
                source = _start_local_attack_demo(seed=int(seed))
            else:
                source = _make_source(
                    mode,
                    uploaded_file=uploaded_file,
                    replay_speed=float(replay_speed),
                    capture_interface=capture_interface,
                    seed=int(seed),
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
