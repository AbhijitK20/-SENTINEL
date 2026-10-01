---
title: SENTINEL - SIH26153
emoji: 🛰️
colorFrom: blue
colorTo: indigo
sdk: streamlit
app_file: streamlit_app.py
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
| **World model (RSSM)** | 0.305 | 0.321 | 0.348 | 0.386 | 0.433 | **+0.189** † |
| Linear transition (stabilized ridge) | 0.616 | 0.616 | 0.617 | 0.619 | 0.627 | −0.429 |
| Same net, no open-loop objective | 0.482 | 0.451 | 0.452 | 0.474 | 0.513 | −0.095 |
| Persistence (repeat last) | 0.307 | 0.451 | 0.470 | 0.487 | 0.530 | 0.000 |

† This table is the 5-horizon **core-comparison** run (`make bench-world`), whose report lands in gitignored `reports/generated/`. The number a reviewer can re-derive from a committed artifact is the 3-horizon release-bundle figure: **mean skill +0.160 on synthetic, -0.171 on real CIC-IDS2017**. Prefer that one when quoting a result.

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
| PR-AUC | 0.978 | 0.995 |

### Real-data forecast (CIC-IDS2017)

The licensed CIC-IDS2017 run is committed as a **derived windowed aggregate** —
`data/derived/cicids2017_windows.parquet`, 4,899 windows x 67 features built from
all eight day CSVs (2,830,743 flows). Aggregates only, no raw flows; citation and
licence terms in `data/derived/PROVENANCE.md`.

On the real test split (818 windows, 41 positive, threshold 0.05) the pipeline is
**worse than its own baseline**:

| Metric | Baseline (logistic) | Temporal (GRU h+1) |
|---|---|---|
| Precision | 0.151 | 0.121 |
| Recall | 0.610 | 0.311 |
| F1 | 0.242 | 0.174 |
| False-positive rate | 0.181 | 0.127 |
| PR-AUC | 0.272 | 0.202 |

The temporal model is worse than the baseline at every horizon. No real-trained
forecasting bundle is shipped for exactly that reason, and the console header
states that the model is synthetic-trained.

What does hold up on real traffic is generalisation to attack stages that were
never in training — leave-one-attack-out over 983 windows at 300 s / 150 s
(698 benign, 285 attack), threshold calibrated on a chronological slice of the
training folds only:

| Held-out stage | Windows | AUC | Benign FPR |
|---|---:|---:|---:|
| Lateral Movement | 28 | 0.780 | 0.7% |
| Credential Access | 58 | 0.772 | 1.1% |
| Reconnaissance | 24 | 0.754 | 4.4% |
| Command and Control | 84 | 0.600 | 2.9% |
| Denial of Service | 53 | 0.564 | 0.1% |
| Initial Access | 38 | 0.401 | 0.0% |

**Mean unseen-stage AUC 0.645, worst benign FPR 4.4%.** Read the AUC column, not
the detection counts: balanced class weights miscalibrate the threshold for a
stage that never appeared in training, so a detection rate in that regime
measures a calibration artifact rather than a capability.

### Withdrawn: the 75-second lead time

Earlier versions of this README published a cross-day lead-time and false-early
table across five CIC-IDS2017 attack families, headed by a **75-second predictive
lead time on Infiltration**. That table is deleted rather than restated, for two
reasons.

1. **It was not reproducible.** The run depended on the licensed raw CSVs, which
   are not committed. No clone could re-derive it, and a number that only one
   machine ever produced is not a result — it is an anecdote.
2. **The committed real-data measurement contradicts it.** The aggregate that *is*
   in this repository puts the temporal model at F1 0.174 against a 0.242
   baseline. A model that loses to its own baseline on real windows does not also
   lead real traffic by half a window, and where the two disagree we publish the
   one a reviewer can re-run.

Every figure on this page comes from a committed artifact. Regenerate them all
with:

```bash
uv run python scripts/export_benchmarks.py
```

### Real-traffic detector validation (lab HTTP attacks)

3/6 claimed detectors fire correctly on real attack traffic through the live path. The recon detector fires on TCP-level port scans but not HTTP enumeration (traversal, enum) — a known limitation documented in the attack scripts. See `scripts/validate_real_detectors.py`.

## How To Run

### Sixty seconds, no dataset download

```bash
uv sync --all-extras
uv run streamlit run src/sentinel/dashboard/app.py   # Dashboard :8501
```

The console opens on the committed release bundle, pre-trained and ready — no
training step, no download. It loads in a few seconds.

Inside **Data source & retraining** you can also switch to
`CIC-IDS2017 pre-windowed (committed)`, which renders **4,899 real CIC-IDS2017
windows in 1.6 s** from `data/derived/cicids2017_windows.parquet`. That file is a
committed aggregate — behavioural features, attack stage and scenario per window,
no raw flows — and it carries the required citation in
`data/derived/PROVENANCE.md`. Reconstructing it from the 1.2 GB source CSVs costs
15-20 minutes and about 11 GB of RAM, so the aggregate is what ships.

The forecasting model itself is trained on the synthetic generator, and the
header says so on every screen. Real windows are shipped for detector
measurement and generalisation evaluation, where the numbers in `research/` come
from.

### Everything else

```bash
# API
uv run uvicorn sentinel.api:create_app --factory --port 8100

# Run with Docker
docker compose up --build -d          # API + dashboard + Prometheus + Grafana
docker compose --profile demo up -d   # + vulnerable target + live sensors

# Re-derive the committed real-data aggregate from the licensed CSVs
uv run python scripts/export_derived_windows.py \
    --data-dir data/raw/cic-ids2017/TrafficLabelling

# Real-data generalisation and detector measurement
uv run python scripts/run_loeo_benchmark.py \
    --data-dir data/raw/cic-ids2017/TrafficLabelling
uv run python scripts/measure_real_detectors.py \
    --data-dir data/raw/cic-ids2017/TrafficLabelling

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
- **World-model open-loop skill is +0.160 on the synthetic release bundle and -0.171 on the real CIC-IDS2017 aggregate** (mean over +1..+3 against persistence). On real traffic it does not beat repeating the last window; it is negative at step +1 on both datasets and only turns positive as persistence itself degrades. No horizon is free
- Imagination does not add lead time on the synthetic set: it matches during-attack detection with a zero false-early rate, but never fires before the attack starts. **No lead-time claim of any kind is made for real traffic** — see the withdrawn section above
- The linear transition baseline cannot simulate: both the one-step and the new multi-step fits are wildly expansive, and the stability projection discards ~99.999% of either, so the shipped linear map is close to a constant predictor. **the world model's open-loop skill is therefore not a like-for-like comparison** — it beats a broken reference, and `rollout_forecast` now emits that caveat on the forecast itself. See `docs/KNOWN_LIMITATIONS.md`
- Packet-level features only reach the model when the input actually contains packet events; a flow CSV produces flow features only and the forecast says so
- **Only the derived CIC-IDS2017 aggregate is committed, never the raw CSVs.** `data/raw/` is gitignored, so `data/derived/cicids2017_windows.parquet` (4,899 windows x 67 features, from 2,830,743 flows) is what ships. That aggregate is enough to reproduce every real-data figure above. Re-running the windowing pass itself, or any benchmark needing packet fields, still requires the licensed CSVs under the dataset's research-use terms — `run_real_benchmark.py` derives its claim status from the input, so a fixture run can never be quoted as a result
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
