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
Network events (flow + packet) → UnifiedEvent → time-windowed NetworkState
    ├── Trained forecaster (logistic baseline + GRU per-horizon)  →  P(infiltration)
    ├── World model (RSSM): latent dynamics, open-loop imagination →  P(infiltration | imagined future)
    ├── 9 attack-type detectors (rule-based, honest)              →  AttackFinding
    └── Stage mapping (MITRE-aligned rules)                       →  stage + evidence
        ↓
    Dashboard / REST API / live sensors / trust ledger
```

## The console

Ten screens, one design system. `src/sentinel/frontend/` owns every colour,
radius and type size; no screen or chart hardcodes one. The rules the system
enforces, and the tests that hold it to them:

- **Time is the spine.** Every trajectory screen renders the same axis in the
  same place, and states the window it is reading.
- **Only probability is bright.** Chrome is neutral; the one perceptually
  uniform risk ramp carries all the meaning, and every value is labelled with
  its band, so colour is never the only carrier.
- **Observed ≠ forecast.** A reserved colour outside the risk ramp, plus a
  persistent legend on every probability surface. A simulation always says it
  is a simulation.
- **Insufficient ≠ low risk.** Unmeasured telemetry renders in its own colour,
  never on the risk ramp.
- **Every number names its method.** A number without a stated method is not
  actionable.
- **Accessibility is tested, not assumed.** All body ink and every ramp step
  clear WCAG AA on every surface they appear on; interactive elements define
  hover, active, focus-visible and disabled; one `prefers-reduced-motion` guard
  covers every transition.

Run it with `uv run streamlit run src/sentinel/dashboard/app.py`. The dataset
selector (synthetic replay, or CIC-IDS2017 attack days when present) sits in the
sidebar, and the training gate is explicit — you see the split before you see a
prediction.

## What's Measured

All numbers come from `reports/generated/` (regenerate with the scripts below). Every number is reproducible, and every number states whether it came from synthetic replay or a real capture.

### World model: open-loop state prediction (held-out scenarios)

The world model is scored on states it has to **imagine**: burn in on observed
history, roll the prior forward with no observations, compare the decoded states
with what actually happened. Skill = `1 − model error / persistence error`;
positive beats repeating the last window. See
`reports/generated/benchmark/world_model/WORLD_MODEL.md`.

| Transition model | +1 | +2 | +3 | +4 | +5 | Mean skill |
|---|---:|---:|---:|---:|---:|---:|
| **World model (RSSM)** | 0.305 | 0.321 | 0.348 | 0.386 | 0.433 | **+0.189** |
| Linear transition (stabilized ridge) | 0.616 | 0.616 | 0.617 | 0.619 | 0.627 | −0.429 |
| Same net, no open-loop objective | 0.482 | 0.451 | 0.452 | 0.474 | 0.513 | −0.095 |
| Persistence (repeat last) | 0.307 | 0.451 | 0.470 | 0.487 | 0.530 | 0.000 |

Three results worth the table:

- The learned dynamics beat both the linear surrogate and doing nothing. The
  linear model's one-step map has spectral norm 2.7 × 10⁵ — it is *expansive*, so
  rolling it out diverges; stabilizing it flattens it toward a constant.
- Removing the open-loop objective — changing nothing else — drops the same
  network below persistence. The multi-step term is what makes imagination work.
- Reconstruction loss disagrees with this ranking: the transformer core
  reconstructs 2.5× better (MSE 0.138 vs 0.345) and simulates worst of the three.

### Synthetic pipeline validation

98 observed features per window: flow aggregations **and** packet-level
attributes (TTL spread, TCP window size, IP fragmentation, retransmissions,
payload distribution).

| Metric | Baseline (logistic) | Temporal (GRU h+1) |
|---|---|---|
| Precision | 0.868 | 1.000 |
| Recall | 0.917 | 0.917 |
| F1 | 0.892 | 0.957 |
| False-positive rate | 0.060 | 0.000 |
| PR-AUC | 0.978 | 1.000 |

### Real-data forecast (CIC-IDS2017, 5 attack families)

Trains on Tuesday (FTP/SSH-Patator), validates on Thursday morning (Web Attacks), tests each day separately.

| Attack Family | Flows | Windows | Lead (0.50) | Crossing | False Early |
|---|---|---|---|---|---|
| Infiltration (Thu PM) | 286K | 97 | **0.5 win (75 s)** | 15% | 11% |
| DDoS (Fri PM) | 225K | 37 | 0.0 | 36% | 9% |
| PortScan (Fri PM) | 286K | 60 | None | 16% | 16% |
| Botnet (Fri AM) | 191K | 97 | 0.0 | 20% | 10% |
| DoS (Wed) | 692K | 204 | 0.0 | 32% | 12% |

The per-horizon model demonstrates **75-second predictive lead time on Infiltration**. Other families show 0.0 lead — the model doesn't predict them ahead of time with current training data. This is an honest result: the architecture works for Infiltration; diverse dwell-time data is needed for other families.

### Real-traffic detector validation (lab HTTP attacks)

3/6 claimed detectors fire correctly on real attack traffic through the live path. The recon detector fires on TCP-level port scans but not HTTP enumeration (traversal, enum) — a known limitation documented in the attack scripts. See `scripts/validate_real_detectors.py`.

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

# Reproduce every measured number
uv run python scripts/run_benchmark.py --output reports/generated/benchmark
uv run python scripts/run_world_model.py \
    --output reports/generated/world-model \
    --baseline reports/generated/benchmark/pipeline/baseline --compare-cores

# Forecast your own capture (PCAP or flow CSV) — fully offline
uv run python scripts/predict_file.py \
    --input data/fixtures/attack_replay.csv \
    --baseline reports/generated/benchmark/pipeline/baseline \
    --temporal reports/generated/benchmark/pipeline/temporal \
    --world-model reports/generated/benchmark/world_model \
    --forecaster imagination --window-seconds 60 --stride-seconds 60 \
    --output reports/generated/file-forecast/forecast.json

# Regenerate the demo capture
uv run python scripts/make_demo_csv.py --output data/fixtures/attack_replay.csv --packet-events

# Real-data protocol (needs the licensed CIC-IDS2017 TrafficLabelling CSVs)
uv run python scripts/run_real_benchmark.py \
    --data-dir data/raw/cic-ids2017/TrafficLabelling \
    --output reports/generated/real-benchmark

# No dataset? Exercise the same code path on a generated CIC-schema fixture.
# The report labels itself SYNTHETIC, so its numbers can never be misquoted.
uv run python scripts/make_cic_fixture.py --output data/raw/fixture-lab
uv run python scripts/run_real_benchmark.py \
    --data-dir data/raw/fixture-lab --output reports/generated/real-fixture

# Tests
uv run pytest -q                       # 300+ tests
uv run ruff check src tests scripts && uv run ruff format --check src tests scripts
```

## Pipeline

- **Ingestion**: CSV flow logs, PCAP packets (Scapy), CIC-IDS2017 adapter, DNS/auth log stubs
- **State builder**: rolling time-window aggregation into `NetworkState`, flow **and** packet level
- **Features**: leakage-safe z-score normalization, scenario-level split manifests
- **Models**: logistic regression baseline, GRU per-horizon temporal, RSSM world model with open-loop imagination, stabilized linear K-step transition rollout
- **Inference**: probability timeline, driving-feature attribution, predicted stage, MITRE mapping, lead time — from a live stream, a replay scenario, or a **PCAP/CSV file**
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
- World-model open-loop skill is measured on synthetic replay only. It degrades with horizon and no horizon is free
- Imagination does not add lead time on the synthetic set: it matches during-attack detection with a zero false-early rate, but never fires before the attack starts — the per-horizon nowcast is what warns early
- The linear transition baseline cannot simulate: its one-step map is expansive, and stabilizing it degenerates to a constant. A multi-step fit is not implemented
- Packet-level features only reach the model when the input actually contains packet events; a flow CSV produces flow features only and the forecast says so
- **The CIC-IDS2017 dataset is not in this repository and is not downloaded by it.** `data/raw/` is gitignored. The real-data protocol is implemented and exercised on a generated CIC-schema fixture, which proves the code path but measures nothing. Real numbers require the licensed CSVs, and `run_real_benchmark.py` derives its claim status from the input so a fixture run can never be quoted as a result
- The trust ledger is a hash chain, not a blockchain — it's the integration seam for a future permissioned chain
- The vulnerable app, attack scripts, and blocklist are local training components — never expose to untrusted networks

## What This Is NOT

- It is not a production IDS. It's a prototype demonstrating predictive forecasting.
- It does not run real blockchain. The trust ledger is a local hash chain.
- It does not replace packet-capture analysis. The feature vectors are flow-derived.
- It does not claim field-validated detection rates. All numbers are lab-measured.
- It does not claim causal explanation. Attributions are model evidence, never proof.

## License

Apache 2.0. See [THIRD_PARTY.md](THIRD_PARTY.md) for dependency licences.
