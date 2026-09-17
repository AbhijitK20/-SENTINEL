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

**AI-Based Network Attack Forecasting from Network Traffic Data**

Licensed under the [Apache License, Version 2.0](LICENSE). See [THIRD_PARTY.md](THIRD_PARTY.md) for dependency licences.

SENTINEL is an offline-first, explainable network attack forecasting and detection platform for **SIH26153: AI based Network Attack Forecasting from Network Traffic Data**.

The system learns how network state changes over time, simulates likely future states, forecasts attacker progression, maps the forecast to recognised MITRE attack stages, detects nine attack types, correlates incidents, and explains the evidence behind each prediction. It also includes a vulnerable local training target, real attack-trigger controls, an Attack Story case study, Grafana observability, and an optional trust-ledger hash chain for tamper-evident alert anchoring.

## What This Platform Does

```
Network events → UnifiedEvent normalization → time-windowed NetworkState
    ├── Trained forecaster (logistic baseline + GRU per-horizon)  →  P(infiltration)
    ├── 9 attack-type detectors (rule-based, honest)              →  AttackFinding
    └── Stage mapping (MITRE-aligned rules)                       →  stage + evidence
        ↓
    Incident correlation + risk fusion + analyst cases + alerts
    ↓
Dashboard / REST API / live sensors / trust ledger
```

**Core differentiator**: Traditional IDS asks "is this flow malicious?" — SENTINEL asks "given the current network trajectory, what is likely to happen next, which assets may be affected, and why?"

## What Has Been Implemented

### Pipeline (Sprints 0–9)

- **Ingestion**: CSV flow logs, PCAP packets (Scapy), CIC-IDS2017 adapter (strict label handling, licensed dataset support), DNS/auth log stubs
- **State builder**: rolling time-window aggregation into `NetworkState` with per-entity and per-edge features
- **Feature schema**: leakage-safe z-score normalization, scenario-level split manifests, contamination audit
- **Models**: logistic regression baseline, GRU per-horizon temporal, recursive K-step rollout transition model
- **Forecast inference**: probability timeline, driving-feature attribution, predicted stage, lead time estimation, MITRE mapping
- **Threshold calibration**: leakage-safe F1/Youden selection, artifact persistence, auto-resolution in all paths
- **Walk-forward replay evaluation**: measured lead time, crossing rate, false-early rate, honest A/B at calibrated and pinned thresholds
- **Synthetic replay generator**: deterministic recon→lateral scenarios for pipeline validation (not benchmark claims)

### Enterprise Platform

- **FastAPI REST API** (`sentinel/api.py`): `/health`, `/model`, `/v1/forecast`, `/v1/detect`, `/v1/events`, `/v1/live`, `/v1/live/reset`, `/v1/alerts`, `/v1/cases`, `/v1/registry`, `/v1/drift`, `/v1/compliance`, `/metrics`
- **API-key auth + RBAC** (`sentinel/auth.py`): 4 roles (viewer/analyst/engineer/admin), SHA-256-hashed keys, append-only audit trail, org_id tenant field
- **Model registry** (`sentinel/registry.py`): register → approve → rollback workflow
- **PSI drift monitoring** (`sentinel/drift.py`): per-feature PSI vs training baseline, `/v1/drift` endpoint
- **Case lifecycle** (`sentinel/cases.py`): OPEN → ACKNOWLEDGED → INVESTIGATING → RESOLVED with SLA
- **Compliance reporting** (`sentinel/compliance.py`): NIST CSF / ISO 27001 / SOC 2 control mapping
- **Federated learning simulation** (`sentinel/federated.py`): FedAvg weights-only sharing
- **HMAC-signed analyst feedback** (`sentinel/feedback.py`): append-only, no auto-retrain
- **Threat-intel enrichment** (`sentinel/threat_intel.py`): URLhaus feed, TTL-bound, list evidence
- **Live push engine** (`sentinel/live.py`): `/v1/events` streams through windowed detection

### Real-Time Detection (Sensors)

- **Packet sensor** (`scripts/packet_sensor.py`): tcpdump lines → per-packet events → `POST /v1/events` — fires rule detectors (recon, DDoS, exfil) on live capture
- **Flow sensor** (`scripts/flow_sensor.py`): tcpdump → 5-tuple flow aggregation (SYN start, RST/FIN teardown, bidirectional) → CICFlowMeter-compatible flow events → **trained forecaster scores live traffic in-distribution**
- **Real nmap demo** (`docker-compose.yml`, profile: `realtime`): genuine SYN scan against a containerized nginx target, detected live by SENTINEL (verified: 4,835 packets → INC-001 Reconnaissance, risk critical)

### Live Threat Intelligence

- **Feed fetcher** (`scripts/fetch_threat_feed.py`): pulls the free URLhaus abuse.ch dump (no API key), handles ZIP-wrapped headerless CSV, writes local JSON snapshot
- **Auto-refresh at boot**: compose `feed-refresher` service refreshes on `docker compose up`, skips when feed is younger than 12h
- **Runtime enrichment**: 19,233 real malicious hosts loaded; C2/exfil scores rise when a destination matches the feed

### Real-Data Training (CIC-IDS2017)

- **Dashboard real-data mode**: sidebar toggle between synthetic and 7 real CIC-IDS2017 attack days (Brute force, DoS variants, Web attacks, Infiltration, Botnet, Port scan, DDoS)
- **Day-level sub-slicing**: each attack day split into half-day scenarios, filtered to attack-carrying slices
- **Stratified splits**: round-robin deal by attack class so every split gets both classes — prevents single-class training failures
- **Verified**: real attack-day flows → model trains on genuine labeled data → forecast tab walks through real attack windows

### Dashboard Interactivity

- **Scenario count**: slider up to 15, IDs generated dynamically (no cap)
- **Forecast walk-forward slider**: choose any point in a scenario; the model input, timeline, stage, evidence, and lead time all update
- **Model score trajectory chart**: what the model would have said at every window, with current cut marked
- **Network States**: log-scale feature chart, per-window model score, attack-stage label, feature-evolution chart with selected window marker, raw edge table
- **Interactive Forecast**: ground-truth strip shows realized attack stages alongside forecast
- **Replay**: walk-forward Forecast-versus-Reality evaluation, scenario switching, downloadable reports, explicit clear-result control, and stale-result invalidation when settings change
- **Demo**: five-step guided replay with safe handling for short or empty scenarios
- **Live Detection**: synthetic, CSV, JSONL, syslog, local capture, attack triggers, detector grid, incident feedback, reset, and stop controls
- **Attack Story**: synthetic Dubsmash-inspired credential-reuse workflow, topology graph, TCP/HTTP/database flow, kill-chain graph, phase replay, containment simulation, and before/after defense comparison

### Next.js Console (`web/apps/console/`)

Production-grade React frontend replacing Streamlit for the analyst surface:

- **RiskMeter**: probability + uncertainty band + numeral, uses SENTINEL risk ramp (`#3E6C8E → #6FA0B8 → #C9B458 → #D98324 → #B33A3A`)
- **StageBadge**: MITRE tactic + technique display
- **DegradedBanner**: honest degradation surface when model unavailable
- **EvidencePanel**: driving-feature attribution breakdown
- **ObservedForecastLegend**: observed vs forecast distinction
- **FlowTable**: flow data table with sorting
- **OverviewPage**: aggregated risk summary
- **Design tokens**: SENTINEL-specific palette, typography, spacing, elevation (`src/sentinel/frontend/tokens.py` → `web/apps/console/src/styles/globals.css`)

```bash
cd web/apps/console
npm install
npm run dev    # http://localhost:3000
```

### Operations

- **GitHub Actions CI** (`.github/workflows/ci.yml`): lint + test (Python 3.11–3.13) + security scan on every push
- **Pre-commit hooks** (`.pre-commit-config.yaml`): ruff lint + format on commit
- **Docker Compose**: local pilot stack (API + dashboard + Prometheus + Grafana)
- **Prometheus + Grafana**: `/metrics` endpoint, auto-provisioned dashboard
- **Live observability metrics**: current events, peak probability, alert-active state, retained findings, emitted windows, incidents, cases, threat-intel indicators, request rate, and latency
- **Hugging Face Spaces**: deploy API or dashboard for free

### Detection

Nine detectors with measured thresholds and honest confidence:

| Detector | MITRE | Signal | Honesty |
|---|---|---|---|
| DDoS | T1498 | Flow/bytes z-score vs benign | Capped 0.95 — can't confirm packet floods from flow data |
| Reconnaissance | T1046 | SYN+RST probe share + low-byte edge fan-out | Fires when ≥6 probe edges and ≥30% probe share |
| Credential abuse | T1110 | Failed auths per minute | Needs ≥3 benign history windows for z-score |
| Lateral movement | T1021 | Bytes on new internal edges unseen in history | Looks back 5 windows for new-edge detection |
| Command & Control | T1071 | Sensor beacon score or threat-intel match | Returns 0.0 with warning when no telemetry — never fabricates |
| Exfiltration | T1048 | Bytes z-score vs history | Guarded by baseline history |
| Insider threat | T1078 | Behavioral z-score on transfer volume | Capped sub-alert during cold start |
| Phishing | T1566 | DNS surrogate (domain length, tunnel marker) | Scores only when DNS features present |
| Malware activity | T1059 | Endpoint execution bursts | Scores only when endpoint telemetry present |

## Quick Start

```bash
# Dependencies
uv sync --all-extras          # everything
uv sync                       # core only (no dashboard, no PyTorch)

# Tests + lint
uv run pytest
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts

# Full benchmark
./run_all.sh                  # lint + tests + benchmark + charts

# Dashboard (Streamlit)
uv run streamlit run src/sentinel/dashboard/app.py

# REST API
uv run uvicorn sentinel.api:create_app --factory --port 8000

# Next.js console (development)
cd web/apps/console && npm install && npm run dev

# Local vulnerable target, scanner, and admin response dashboard
docker compose --profile demo up -d
```

## Docker Compose (Local Pilot)

```bash
# Default stack: API + dashboard + Prometheus + Grafana
docker compose up -d

# Dashboard: http://localhost:8501
# API docs:  http://localhost:8000/docs
# Grafana:   http://localhost:3000  (admin/admin)
# Prometheus: http://localhost:9090/targets
```

The demo admin dashboard is available at `http://localhost:5001`; the
intentionally vulnerable training target is at `http://localhost:5000`.
The admin surface exposes attack triggers, `Reset System`, `Block All
Attackers`, and `Unblock All`. Reset clears the in-memory live detection demo
session and demo blocklist; it does not repair a real system or erase forensic
evidence.

Grafana's `SENTINEL API Overview` dashboard includes current live-state panels.
The live panels use `last_over_time(...[5m])`, so reset values appear as
explicit zeroes rather than an ambiguous `No data` state:

- `sentinel_live_events_seen`
- `sentinel_live_peak_probability`
- `sentinel_live_alert_active`
- `sentinel_live_findings`

## Real-Time Threat Intel

```bash
# Pull the free URLhaus feed (no API key needed)
uv run python scripts/fetch_threat_feed.py
# Saves to reports/threat_intel/feed.json (git-ignored)

# Or via compose (runs at boot, skips if < 12h old)
docker compose run --rm feed-refresher
```

## Real-Network Detection Demo

```bash
# Run a genuine nmap SYN scan against a containerized target;
# SENTINEL detects it live via tcpdump capture on the wire.
export SENTINEL_API_KEY=sent_<your-key>
docker compose --profile realtime up -d
docker compose logs -f demo-sensor demo-attacker
```

## Real-Data Training (CIC-IDS2017)

The dashboard offers a **Real CIC-IDS2017 attacks** data-source toggle in the sidebar. If the dataset exists under `data/raw/cic-ids2017/TrafficLabelling/`, you can select any combination of attack days:

| Day | Attack Type |
|---|---|
| Tuesday | FTP/SSH brute force (Patator) |
| Wednesday | DoS (4 variants + Heartbleed) |
| Thursday morning | Web attacks (XSS / SQLi / Brute) |
| Thursday afternoon | Infiltration (metasploit) |
| Friday morning | Botnet C2 |
| Friday afternoon | Port scan (nmap) + DDoS |

Retrain on a different day subset → different data → different model. No data leaves the machine.

## Core Differentiator

Traditional intrusion detection asks: "Is this flow malicious?"

SENTINEL asks: "Given the current network trajectory, what is likely to happen next, which assets may be affected, and why?"

Every forecast carries driving-feature attribution, every detection carries measured thresholds and explicit confidence, and every honest limitation is documented — never hidden.

## Attack Simulation And Case Study

The local demo target on port 5000 is intentionally vulnerable and uses only
synthetic seeded data. The port-5001 admin dashboard can launch brute force,
SQL injection, port scan, XSS, directory traversal, API enumeration,
credential stuffing, and a combined attack chain.

The `Attack Story` tab is an educational, synthetic Dubsmash-inspired case
study. Public reporting confirms the historical breach impact and exposed data
categories, but not every technical step represented by this demo. The story
is therefore labelled illustrative rather than a reconstruction of
undocumented historical internals.

```text
synthetic attack -> vulnerable app logs -> scanner -> /v1/events
    -> event-time windows -> detectors + forecast -> incident correlation
    -> admin investigation -> simulated containment -> report/metrics
```

## Claims And Limitations

- Synthetic replay validates pipeline behavior, not production detection performance.
- Replay lead time is currently measured at 0.0 windows on the available synthetic and checked-in real-data artifact paths because stage transitions occur within the window granularity.
- Precursor windows may remain labelled `Benign` while intentionally triggering early-warning detectors; these are not ordinary benign-only false-positive measurements.
- The vulnerable app, attack scripts, blocklist, and containment buttons are local training components and must not be exposed to untrusted networks.
- Grafana and the admin dashboard are observability/demo surfaces, not production SOAR controls.

## Documentation Map

- **Status**: `IMPLEMENTATION_STATUS.md` (sprints 0–11, current limitations), `RESULTS.md` (measured numbers), `QUALITY_GATES.md` (per-gate evidence)
- **Product**: `PROJECT_CHARTER.md`, `VISION_AND_POSITIONING.md`, `PRD.md`, `REQUIREMENTS.md`, `DESIGN.md` (design direction, risk ramp, canvas, typography)
- **Technical**: `ARCHITECTURE.md`, `DATASET_PLAN.md`, `DATA_CONTRACTS.md`, `MODEL_PLAN.md`
- **Quality**: `EVALUATION_PLAN.md`, `EXPLAINABILITY_PLAN.md`, `TEST_STRATEGY.md`, `KNOWN_LIMITATIONS.md`
- **Security**: `SECURITY.md` (disclosure policy, SLA), `SENTINEL_PRODUCTION_PLAN.md` (threat model, STRIDE)
- **Operations**: `CHANGELOG.md`, `docs/adr/0001-feature-versioning.md`, `docs/runbooks/alert-high-cpu.md`, `docs/runbooks/forecast-latency-high.md`
- **Detectors**: `DETECTORS.md` (attack-type detectors, incident correlation, asset risk fusion)
- **Enterprise**: `ROADMAP.md` (scale levels, phase status) + `DEPLOYMENT.md` (compose stack, Hugging Face Spaces, observability, real-data mode, sensors)
- **Platform modules**:
  - `sentinel/api.py` — REST API (forecast, detect, events, alerts, cases, registry, drift, compliance, metrics, auth)
  - `sentinel/auth.py` — API-key auth, RBAC, audit trail
  - `sentinel/live.py` — live detection engine (5 sources: CSV, JSONL, syslog, Scapy, flow sensor)
  - `sentinel/detectors.py` — 9 attack-type detectors with measured thresholds
  - `sentinel/correlation.py` — incident correlation with risk fusion
  - `sentinel/cases.py` — case lifecycle + SLA
  - `sentinel/drift.py` — PSI monitoring
  - `sentinel/registry.py` — model promotion workflow
  - `sentinel/compliance.py` — NIST / ISO / SOC 2 control mapping
  - `sentinel/federated.py` — FedAvg simulation
  - `sentinel/feedback.py` — HMAC-signed analyst feedback
  - `sentinel/threat_intel.py` — keyless threat-intel feed enrichment
  - `scripts/fetch_threat_feed.py` — internet-fetched feed refresh
  - `scripts/flow_sensor.py` — 5-tuple flow aggregation from tcpdump
  - `scripts/packet_sensor.py` — per-packet event stream from tcpdump
- **Delivery**: `SPRINT_PLAN.md`, `DEMO_PLAN.md`, `DEMO_SCENARIO.md`, `SUBMISSION_PLAN.md`
- **Presentation**: `PRESENTATION_OUTLINE.md` (content), `scripts/build_deck.py` (generates `deliverables/Trajectory_SIH26153_Idea_Deck.pptx` and `.pdf`)

## Source Of Truth

The official SIH 2026 listing is the source for problem-statement compliance. Product decisions are recorded in this repository and must not claim capabilities that are not implemented and tested.
