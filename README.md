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

Sentinel predicts what happens next in a network attack — not just what's happening now. Traditional IDS asks "is this flow malicious?" Sentinel asks "given the current trajectory, what is the attacker likely to do next, which assets may be affected, and why?"

Every prediction carries driving-feature attribution, every detection carries measured thresholds and explicit confidence, and every honest limitation is documented — never hidden.

```
Network events → UnifiedEvent normalization → time-windowed NetworkState
    ├── Trained forecaster (logistic baseline + GRU per-horizon)  →  P(infiltration)
    ├── 9 attack-type detectors (rule-based, honest)              →  AttackFinding
    └── Stage mapping (MITRE-aligned rules)                       →  stage + evidence
        ↓
    Dashboard / REST API / live sensors / trust ledger
```

## What's Measured

All numbers come from `reports/generated/` (regenerate with the scripts below). Every number is reproducible.

### Synthetic pipeline validation

| Metric | Baseline (logistic) | Temporal (GRU) |
|---|---|---|
| Precision (h+1) | 0.714 | 0.833 |
| Recall (h+1) | 0.833 | 0.940 |
| F1 (h+1) | 0.769 | 0.886 |
| PR-AUC | 0.940 | 0.959 |

### Real-data forecast (CIC-IDS2017, cross-day temporal split)

| Threshold | Forecaster | Median lead | Crossing rate | False early |
|---|---|---|---|---|
| 0.50 (default) | Per-horizon | **0.5 windows (75 s)** | 15% | 11% |
| 0.50 (default) | Recursive rollout | 0.0 | 88% | 58% |

Test phase: Thursday afternoon Infiltration (36 attack flows vs ~287k benign). The per-horizon model detects infiltration 75 seconds before it fully materializes, with 11% false-early rate. See `reports/generated/real-benchmark/REAL_BENCHMARK.md`.

### Real-traffic detector validation (lab HTTP attacks)

3/6 claimed detectors fire correctly on real attack traffic through the live path. See `scripts/validate_real_detectors.py`.

## How To Run

```bash
# Install
uv sync --all-extras

# Run locally
uv run streamlit run src/sentinel/dashboard/app.py    # Dashboard :8501
uv run uvicorn sentinel.api:create_app --factory --port 8100  # API :8100

# Run with Docker
docker compose up --build -d          # API + dashboard + Prometheus + Grafana
docker compose --profile demo up -d   # + vulnerable target + live sensors

# Tests
uv run pytest -q                       # 300+ tests
uv run ruff check src tests scripts && uv run ruff format --check src tests scripts
```

## Pipeline

- **Ingestion**: CSV flow logs, PCAP packets (Scapy), CIC-IDS2017 adapter, DNS/auth log stubs
- **State builder**: rolling time-window aggregation into `NetworkState` with per-entity and per-edge features
- **Features**: leakage-safe z-score normalization, scenario-level split manifests
- **Models**: logistic regression baseline, GRU per-horizon temporal, recursive K-step rollout
- **Inference**: probability timeline, driving-feature attribution, predicted stage, MITRE mapping, lead time
- **Calibration**: leakage-safe F1/Youden threshold selection

## Nine Detectors

| Detector | MITRE | What It Watches | Honesty |
|---|---|---|---|
| DDoS | T1498 | Flow/bytes z-score vs benign | Capped 0.95 — can't confirm packet floods from flow data |
| Recon | T1046 | SYN+RST probe share + low-byte fan-out | Fires when ≥6 probe edges and ≥30% share |
| Credential abuse | T1110 | Failed auths per minute | Needs ≥3 benign history windows |
| Lateral movement | T1021 | Bytes on new internal edges | Looks back 5 windows |
| C2 beacon | T1071 | Sensor beacon score or threat-intel match | Returns 0.0 when no telemetry — never fabricates |
| Exfiltration | T1048 | Bytes z-score vs history | Guarded by baseline history |
| Insider threat | T1078 | Behavioral z-score on transfer volume | Capped during cold start |
| Phishing | T1566 | DNS surrogate (domain length, tunnel marker) | Scores only with DNS features |
| Malware | T1059 | Endpoint execution bursts | Scores only with endpoint telemetry |

## Docker Compose

```bash
docker compose up --build -d
# Dashboard:  http://localhost:8501
# API docs:   http://localhost:8100/docs
# Grafana:    http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090/targets
```

## Real-Network Demo

```bash
# Genuine nmap SYN scan — Sentinel detects it live
docker compose --profile realtime up --build -d
docker compose logs -f demo-sensor demo-attacker
```

## Honest Limitations

- Synthetic replay validates pipeline behavior, not production detection performance
- Replay lead time is 0.0 windows on synthetic data because stage transitions occur within window granularity
- Real-traffic forecasting is unmeasured — the CIC-IDS2017 adapter exists but licensed dataset run is pending
- The trust ledger is a hash chain, not a blockchain — it's the integration seam for a future permissioned chain
- The vulnerable app, attack scripts, and blocklist are local training components — never expose to untrusted networks

## What This Is NOT

- It is not a production IDS. It's a prototype demonstrating predictive forecasting.
- It does not run real blockchain. The trust ledger is a local hash chain.
- It does not replace packet-capture analysis. The feature vectors are flow-derived.
- It does not claim field-validated detection rates. All numbers are lab-measured.

## License

Apache 2.0. See [THIRD_PARTY.md](THIRD_PARTY.md) for dependency licences.
