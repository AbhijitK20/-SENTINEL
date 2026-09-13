---
title: SENTINEL - SIH26153
emoji: Shield
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8501
pinned: false
---

# SENTINEL

SENTINEL is an offline, explainable network attack forecasting prototype for **SIH26153: AI based Network Attack Forecasting from Network Traffic Data**.

The system is intended to learn how network state changes over time, simulate likely future states, forecast attacker progression, map the forecast to recognised attack stages, and explain the evidence behind each prediction.

## Current Status

**Sprints 0-8 complete on synthetic replay data: ingestion, states, leakage-safe targets, baseline and GRU temporal models, forecast inference with MITRE-oriented stage mapping, calibrated thresholding, recursive rollout, walk-forward replay evaluation, dashboard with guided demo, and a one-command reproducible benchmark.** See `IMPLEMENTATION_STATUS.md` for exact scope and limitations, `RESULTS.md` for measured numbers, and `QUALITY_GATES.md` for per-gate evidence.

The one explicitly open item: a licensed real-data run (CIC-IDS2017 adapter is implemented and fixture-tested; download + licence review pending).

## Quick Start

```bash
uv sync                                 # core dependencies
uv sync --extra deep-learning           # + PyTorch for temporal model
uv sync --extra dashboard               # + Streamlit/Plotly for the demo
./run_all.sh                            # lint + tests + full benchmark + charts
uv run pytest                           # 92 tests
uv run python scripts/run_baseline.py   # baseline -> reports/generated/baseline/
uv run python scripts/run_temporal.py   # temporal -> reports/generated/temporal/
uv run python scripts/run_comparison.py # side-by-side -> reports/generated/comparison/
uv run python scripts/run_replay.py     # walk-forward forecast-vs-reality
uv run python scripts/run_rollout.py    # recursive rollout comparison
uv run streamlit run src/trajectory/dashboard/app.py   # analyst demo UI (now with Live Detection tab)

# Live demo: train in the dashboard, open Live Detection, press Start.
# Or run the pieces manually (two terminals):
uv run python scripts/attack_demo.py target                      # localhost echo target
uv run python scripts/attack_demo.py attack --speed 2            # scripted attack → events.jsonl
```

For local packet-derived signals, install Scapy and select `Local loopback capture`
in the Live Detection tab:

```bash
uv sync --extra dashboard --extra pcap
sudo -E uv run streamlit run src/trajectory/dashboard/app.py
```

Use interface `lo` on Linux. The localhost attack button remains a flow/JSONL
sensor demo; loopback capture is the separate packet-feature path.

To feed the live engine from an existing log pipeline, select `Syslog log file`
in the Live Detection tab (or tail a file directly):

```python
from trajectory.live import LiveEngine, SyslogTailSource

source = SyslogTailSource("/var/log/sensor.log")
```

Lines follow `<ISO-8601 or epoch timestamp> <host> <app> k=v …` — e.g.
`2026-01-01T00:00:10+00:00 host-01 authd src=10.0.0.9 dst=auth-service
failed_auth=yes bytes=300`. Recognized keys become detector features;
unparseable lines are counted and skipped, never fatal.

Optional extras: `--extra pcap` (Scapy), `--extra dashboard`, or `--group presentation` for the slide generator.

Baseline and temporal runs write JSON results (with model SHA-256 checksums) and Markdown reports. Numbers from synthetic data are pipeline checks, not benchmark claims — the claim status is stated in `RESULTS.md` and in every generated report.

## Core Differentiator

Traditional intrusion detection asks: "Is this flow malicious?"

Trajectory asks: "Given the current network trajectory, what is likely to happen next, which assets may be affected, and why?"

## Documentation Map

- Product: `PROJECT_CHARTER.md`, `VISION_AND_POSITIONING.md`, `PRD.md`, `REQUIREMENTS.md`
- Agile: `EPICS.md`, `USER_STORIES.md`, `FEATURE_CATALOG.md`, `PRODUCT_BACKLOG.md`, `AGILE_WORKFLOW.md`
- Technical: `ARCHITECTURE.md`, `DATASET_PLAN.md`, `DATA_CONTRACTS.md`, `FEATURE_SPECIFICATION.md`, `MODEL_PLAN.md`
- Quality: `EVALUATION_PLAN.md`, `EXPLAINABILITY_PLAN.md`, `TEST_STRATEGY.md`, `QUALITY_GATES.md`, `KNOWN_LIMITATIONS.md`
- Detectors: `DETECTORS.md` (attack-type detectors, incident correlation, asset risk fusion)
- Platform: `ROADMAP.md` (enterprise roadmap, scale levels, phase status) + `trajectory/api.py` (FastAPI service: forecast/detect/alerts plus `/v1/cases` case lifecycle, `/v1/registry` model promotion, `/v1/drift` PSI checks, `/v1/compliance` control report, `/v1/events` live push, `/metrics` Prometheus endpoint, key-based auth with RBAC and audit — see `trajectory/auth.py`)
- Operations: model promotion in `trajectory/registry.py`, PSI drift monitoring in `trajectory/drift.py`, case lifecycle + SLA in `trajectory/cases.py`, compliance mapping in `trajectory/compliance.py`, FedAvg simulation in `trajectory/federated.py`, HMAC-signed feedback in `trajectory/feedback.py`, keyless threat-intel feeds in `trajectory/threat_intel.py`
- Deployment: API container (`Dockerfile.api`) with env-var config and artifact bootstrap for Hugging Face Spaces; observability stack (`docker compose --profile obs up`) — see `DEPLOYMENT.md`
- Delivery: `SPRINT_PLAN.md`, `DEMO_PLAN.md`, `DEMO_SCENARIO.md`, `SUBMISSION_PLAN.md`
- Presentation: `PRESENTATION_OUTLINE.md` (content), `scripts/build_deck.py` (generates `deliverables/Trajectory_SIH26153_Idea_Deck.pptx` and `.pdf`)

## Source Of Truth

The official SIH 2026 listing is the source for problem-statement compliance. Product decisions are recorded in this repository and must not claim capabilities that are not implemented and tested.
