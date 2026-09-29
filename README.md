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

**An offline, explainable temporal cyber-defence system for forecasting likely
attack progression from network traffic before compromise is complete.**

SENTINEL asks a question a traditional IDS does not: given the current
trajectory, what stage is the attack at, which assets are exposed, and why does
the system think so. It is a research prototype, not a production SOC platform,
and it does not claim field-validated detection rates.

Every prediction carries driving-feature attribution, every detection carries
measured thresholds and explicit confidence, and every honest limitation is
documented rather than hidden — including several that make the project look
worse than a marketing deck would.

## Problem

Security teams learn about an intrusion when it has already happened. A typical
IDS scores each flow in isolation, so it answers *"is this flow malicious?"* and
nothing else. It has no memory of a trajectory, which means:

- by the time exfiltration is detected, the data has already left;
- a brute-force burst and a single mistyped password look alike at flow level;
- a late alert tells the analyst nothing about what is likely to come next, or
  which assets are exposed, or why the alert matters.

## Solution

SENTINEL is an **offline, explainable temporal cyber-defence research
prototype**. It treats network traffic as a trajectory rather than a snapshot,
and forecasts attack progression so a human has a chance to act. Every
probability ships with the evidence behind it, and where a measurement does not
exist the project prints `PENDING` rather than a plausible number.

It is a research prototype. It is not a production SOC platform and does not
claim field-validated detection rates.

## How it works

```text
Network traffic (flow CSV / PCAP)
        ↓
Windowed feature extraction          60 s windows, flow + packet level, 98 features
        ↓
Detection layer                      9 MITRE-mapped rule detectors + calibrated baseline
        ↓
Temporal attack-stage estimation     RSSM world model, per-horizon GRU
        ↓
Risk + explanation                   calibrated probability, conformal interval,
                                     driving-feature attribution, counterfactual
        ↓
Tamper-evident alert history         append-only hash chain, verified on read
```

Every stage in that chain is implemented and exercised by the test suite.

## Key capabilities

Each of these is implemented in `src/sentinel/` and covered by the suite; a
reachability gate fails the build if any module stops being reachable from an
entry point.

| Capability | Where |
|---|---|
| Network traffic analysis from flow CSV **and** PCAP | `ingestion.py`, `pcap_ingestion.py` |
| Both flow and packet-level telemetry in one window (TTL spread, TCP window, fragmentation, retransmission) | `state_builder.py`, `feature_computes/` |
| Attack-stage detection and estimation, MITRE-mapped with evidence | `detectors.py`, `stage_mapping.py` |
| Temporal context across a window sequence | `temporal.py` (per-horizon GRU), `world_model/` (RSSM) |
| Open-loop imagination — scoring states the model had to imagine | `world_model/imagine.py` |
| Risk scoring with a calibrated decision threshold | `calibration.py`, `isotonic.py` |
| Conformal prediction intervals with a finite-sample coverage claim | `conformal.py` |
| Explainable findings: driving-feature attribution and counterfactuals | `explain/` |
| Alert provenance — hashes and forecast metadata, no raw traffic | `ledger.py` |
| Tamper-evident history — an append-only hash chain, verified on read | `ledger.py` |
| Offline, local execution — no network client in `src/sentinel/`, enforced by a test | `test_offline.py` |
| Streamlit analyst console, 10 screens | `dashboard/` |
| FastAPI service, 21 routes with API-key RBAC | `api/app.py` |
| Reproducible evaluation — scenario-level splits, train-only statistics, SHA-256 bundle | `tests/`, `models/release/` |

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
sidebar. By default the console loads the committed release bundle and trains
nothing; training only happens if you point it at a data source with no bundle,
and the scenario-level train/validation/test split is applied before any fit, so
a window from a training scenario never reaches the model under test.

## What's Measured

Every number below is read from the committed, SHA-256-verified release bundle in
`models/release/v1/`, produced on `synthetic-recon-lateral-v3` with seed 42 and
10 scenarios split 60/20/20 **by scenario** — no window from a training
scenario appears in the test set. 98 features per window, 60 s windows, 30 s
stride. The bundle is regenerated by `make reproduce` and re-hashed by
`make verify`; the reports under `reports/generated/` are not committed and are
rebuilt on demand.

### Infiltration detection (test split, 104 windows, 42 positive)

| Model | Precision | Recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|
| Logistic baseline | 0.635 | 0.786 | 0.702 | 0.662 |
| GRU h+1 (per-horizon) | 0.745 | 0.905 | 0.817 | 0.885 |

### World model — RSSM, test split

| Quantity | Value |
|---|---:|
| Attack-stage accuracy | 0.880 |
| Stage macro-F1 | 0.877 |
| Risk-head F1 / PR-AUC | 0.826 / 0.918 |
| **Open-loop skill vs persistence** | **-0.001** |
| Open-loop skill per step (+1, +2, +3) | -0.282, +0.122, +0.156 |
| KL divergence (nats) | 0.071 |

Open-loop skill is `1 - model error / persistence error`, so positive beats
repeating the last window. **It is currently near zero**: the world model is not
yet beating the trivial baseline when it has to imagine the future with no
observations. That is reported, not tuned away. See
`docs/KNOWN_LIMITATIONS.md`.

### Detectors (test split, `make bench-detectors`)

| Rule | Precision | Recall | F1 |
|---|---:|---:|---:|
| reconnaissance | 0.676 | 0.962 | 0.794 |
| lateral_movement | 0.765 | 0.481 | 0.591 |

The other seven rules have no ground-truth stage in this dataset and are
reported as *not evaluable* rather than scored against a label they cannot
have.

### Why these numbers are lower than an earlier release

The first synthetic corpus was **trivially separable**. Each phase drew from a
disjoint band of byte volumes, port sets, destination hosts and TCP flag words,
so the label was recoverable from one scalar:

| | v2 (shortcut) | **v3 (current)** |
|---|---:|---:|
| best single-feature ROC-AUC | 0.9833 | **0.7407** |
| full baseline ROC-AUC | 0.9933 | **0.9302** |
| **full minus single — the gap** | **0.0072** | **+0.1126** |

On v2, 97 of 98 features were decoration and every headline number measured the
shortcut. `synthetic-recon-lateral-v3` overlaps the classes deliberately: benign
traffic is a mixture including bulk transfers and established sessions whose
volume spans the attack phases, destinations and ports come from shared pools,
and phase lengths vary per scenario.

**The headline got worse because it was measuring the wrong thing.** The gap is
the number that means something. Reproduce with
`uv run python scripts/diagnose_separability.py`; the regression is gated by
`tests/test_benchmark_separability.py`.

This remains a synthetic benchmark. It shows the pipeline learns structure
rather than a volume shortcut. It is **not** evidence of real-world forecasting
ability.

### Real-data forecast (CIC-IDS2017) — PENDING, NOT YET MEASURED

> **Claim status: unverified — no result is published here.** The cross-day
> CIC-IDS2017 forecast protocol is implemented (`scripts/run_real_benchmark.py`)
> and exercised on a generated CIC-schema fixture, which proves the code path
> but measures nothing. The licensed CSVs are **not in this repository** and are
> not downloaded by it; `data/raw/` holds only `fixture-lab/`, a synthetic file
> this project generates.
>
> A lead-time and false-early table for five attack families was published here
> previously and is **withdrawn** — it cited `reports/generated/real-benchmark/`,
> which does not exist in this repository. An earlier version of this README
> also stated a specific predictive lead time on the Infiltration family; that
> number came from the withdrawn table, is not supported by any artifact here,
> and `tests/test_claims_integrity.py` fails the build if it returns.
>
> **To make this real:** obtain the licensed CSVs, place them in
> `data/raw/cic-ids2017/TrafficLabelling/`, run `make bench-real`, and commit the
> generated report. `run_real_benchmark.py` derives its own claim status from
> the input, so a fixture run can never be quoted as a real-data result.

### Real-traffic detector validation (lab HTTP attacks)

3 of 6 claimed detectors fire correctly on real attack traffic through the live
path. The recon detector fires on TCP-level port scans but not HTTP enumeration
(traversal, enum) — a known limitation documented in the attack scripts. See
`scripts/validate_real_detectors.py`.

### Detectors

| Detector | MITRE | What it watches | Honesty |
|---|---|---|---|
| DDoS | T1498 | Flow/bytes z-score vs benign | Capped 0.95 — flow data cannot confirm packet floods |
| Recon | T1046 | SYN+RST probe share + low-byte fan-out | Needs >=8 flows before a share is scored; evidence-only on real flow telemetry |
| Credential abuse | T1110 | Failed auths per minute, from the window count | Flow telemetry sees counts, not per-edge auth outcomes |
| Lateral movement | T1021 | Byte rate on already-seen internal edges | Absolute band; **capped sub-alert without a DeploymentBaseline**, which does not exist yet |
| C2 beacon | T1071 | Sensor beacon score or threat-intel match | Returns 0.0 with no telemetry — never fabricates |
| Exfiltration | T1048 | Bytes z-score vs history | **Capped sub-alert without a DeploymentBaseline**; heavy-tailed volume cannot separate a backup from a transfer on 3-6 windows |
| Insider threat | T1078 | Behavioural z-score on transfer volume | Capped during cold start |
| Phishing | T1566 | DNS surrogate | Disabled without DNS features |
| Malware | T1059 | Endpoint execution bursts | Disabled without endpoint telemetry |

Six of nine rules can be evaluated on this dataset. The other three require DNS
or EDR telemetry the corpus does not carry.

## How To Run

Everything below was executed against this repository on 2026-09-29 from a
clean clone. Where a command is not exercised here it says so.

### Prerequisites

| | |
|---|---|
| Python | 3.11–3.13 (`uv` will fetch one; `pyproject.toml` caps at `<3.14`) |
| uv | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| RAM | ~2 GB. The bundle loads torch; a cold dashboard boot trains models if no bundle is found. |
| Disk | ~1.5 GB for the virtualenv. **The Docker image is larger** — it bundles torch CPU — and needs ~6 GB free. |
| Docker | Optional. Only for `docker compose`. |

### Install

```bash
uv sync --all-extras --all-groups
```

### Run locally (the path verified for this submission)

```bash
# Dashboard — http://127.0.0.1:8501
SENTINEL_ARTIFACTS_DIR=models/release/v1 \
uv run streamlit run src/sentinel/dashboard/app.py \
    --server.address 127.0.0.1 --server.port 8501

# API — http://127.0.0.1:8100  (docs at /docs)
SENTINEL_ARTIFACTS_DIR=models/release/v1 \
SENTINEL_BOOTSTRAP_KEY="$(openssl rand -hex 16)" \
uv run uvicorn sentinel.api:create_app --factory --host 127.0.0.1 --port 8100
```

The dashboard loads the committed, checksummed bundle from
`models/release/v1/`, so no training happens on start. Measured: dashboard
health `ok`, first render 3.7 s, subsequent reruns 0.30 s with all ten screens
present and no exceptions.

### Demo mode, and when to turn it off

Demo mode is **on by default** so this project runs with no setup. In demo mode
the API accepts a published, well-known key (`sent_demo_key_2026`) and
`/health` reports `"demo_mode": true`.

```bash
SENTINEL_DEMO_MODE=false SENTINEL_BOOTSTRAP_KEY=<your secret> \
  uv run uvicorn sentinel.api:create_app --factory --host 0.0.0.0 --port 8100
```

With demo mode off the app **refuses to start** rather than serving an
unauthenticated API, and it rejects the published demo key outright. Verified
both refusals. The dashboard's "Initiate Attack" button additionally requires
the Streamlit server to be bound to loopback, because it spawns
`scripts/full_attack.py` as a subprocess and Streamlit has no authentication of
its own. Every variable is documented in `.env.example`.

### Smoke test — run this before a demo

```bash
uv run python scripts/smoke_demo.py
```

Seven steps through the path a judge will see — artifacts load, windows build,
detectors fire, a forecast explains itself, a stage maps, the ledger verifies,
and the committed fixture forecasts. It prints the measured value for each
step and exits non-zero on the first failure. Passing output from this tree:

```
ok    release artifacts present and checksummed — 98 features, threshold 0.45
ok    synthetic scenario generates windows — 66 windows, 2 telemetry levels
ok    detectors fire on an attack window — 25 alerts, e.g. [...]
ok    forecast produces a timeline with attribution — h+5 P=0.761, top driver packets_max (+6.50), stage Lateral Movement
ok    stage mapping returns a named stage or says why not — 'Lateral Movement'
ok    trust ledger records and verifies — 3 records, chain valid
ok    file forecast works on the committed fixture — 3 horizons, packet coverage True
```

### Judge flow (verified)

Dashboard **Forecast** tab, or `POST /v1/detect` with the committed fixture:

```bash
KEY=sent_demo_key_2026   # demo mode; see "Demo mode" above
curl -s -X POST http://127.0.0.1:8100/v1/detect \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d "$(uv run python -c '
import json,sys
from sentinel.ingestion import read_flow_csv
ev=list(read_flow_csv("data/fixtures/attack_replay.csv").events)
print(json.dumps({"events":[e.model_dump(mode="json") for e in ev],
                  "window_seconds":60,"stride_seconds":60}))')"
```

Returns findings and alerts per window; then `POST /v1/forecast` on the same
events returns the probability timeline, the predicted stage with its MITRE
reference, and the driving features behind it. Measured on the fixture: 360
findings / 19 alerts across five attack types, stage `Lateral Movement`
(TA0008), top driver `packets_max +3.66`.

### With Docker

```bash
docker compose up --build -d          # API + dashboard (default profile only)
docker compose --profile demo up -d   # + vulnerable target + live sensors
docker compose --profile obs up -d    # + Prometheus + Grafana
```

The default profile is `api` and `dashboard` only. Prometheus and Grafana are
behind the `obs` profile, not the default.

**The IDURAR lab scenario needs a sibling repository this one does not contain.**
Those services moved to `docker-compose.lab.yml` on 2026-09-29; until then,
`docker compose --profile lab up` failed on a fresh clone because Compose
resolves the build context of every profiled service. To use it:

```bash
git clone <idurar-erp-crm-url> ../idurar-erp-crm
docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile lab up -d
```

Everything else — the dashboard, the API, the detectors, the synthetic replay —
runs with `docker compose up -d` and needs no sibling checkout.

### Reproduce the measured numbers

```bash
uv run python scripts/run_benchmark.py --output reports/generated/benchmark
uv run python scripts/run_world_model.py \
    --output reports/generated/world-model \
    --baseline reports/generated/benchmark/pipeline/baseline --compare-cores
uv run python scripts/diagnose_separability.py   # the shortcut-leakage check
uv run python scripts/sweep_known_edge_band.py    # the detector band sweep
```

The generated reports are **not committed** (`reports/generated/` is
gitignored) and are rebuilt on demand. `make reproduce` runs the whole chain.

### Forecast your own capture (PCAP or flow CSV) — fully offline

```bash
uv run python scripts/predict_file.py \
    --input data/fixtures/attack_replay.csv \
    --baseline models/release/v1 --temporal models/release/v1 \
    --world-model models/release/v1 \
    --forecaster imagination --window-seconds 60 --stride-seconds 60 \
    --output reports/generated/file-forecast/forecast.json
```

### Real-data protocol (needs the licensed CIC-IDS2017 CSVs)

```bash
uv run python scripts/run_real_benchmark.py \
    --data-dir data/raw/cic-ids2017/TrafficLabelling \
    --output reports/generated/real-benchmark
```

No dataset? Exercise the same code path on a generated CIC-schema fixture. The
report labels itself SYNTHETIC, so its numbers can never be misquoted:

```bash
uv run python scripts/make_cic_fixture.py --output data/raw/fixture-lab
uv run python scripts/run_real_benchmark.py \
    --data-dir data/raw/fixture-lab --output reports/generated/real-fixture
```

### Tests

```bash
uv run pytest -q
uv run ruff check src tests scripts && uv run ruff format --check src tests scripts
```

## Docker Compose

```bash
docker compose up --build -d
# Dashboard:  http://127.0.0.1:8501
# API docs:   http://127.0.0.1:8100/docs

docker compose --profile obs up -d
# Grafana:    http://127.0.0.1:3000  (credentials are set in compose; see the file)
# Prometheus: http://127.0.0.1:9090/targets
```

Both published ports bind to **loopback**, not `0.0.0.0`. The dashboard hosts the
attack-runner button, and the API is authenticated; neither belongs on a public
interface. The Grafana admin password is still the compose default
(`admin`) — that is a demo convenience and should be set before any shared
deployment.

## Real-Network Demo

```bash
# Genuine nmap SYN scan — Sentinel detects it live
docker compose --profile realtime up --build -d
docker compose logs -f demo-sensor demo-attacker
```

## Demo flow

Verified end to end on this repository. Every step below was executed; the
observed output is quoted so a judge knows what to expect rather than what to
hope for.

```bash
# 1. Start SENTINEL
uv sync --all-extras --all-groups
SENTINEL_ARTIFACTS_DIR=models/release/v1 \
SENTINEL_BOOTSTRAP_KEY="$(openssl rand -hex 16)" \
uv run uvicorn sentinel.api:create_app --factory --host 127.0.0.1 --port 8100 &
SENTINEL_ARTIFACTS_DIR=models/release/v1 \
uv run streamlit run src/sentinel/dashboard/app.py \
    --server.address 127.0.0.1 --server.port 8501
```

2. **Open the dashboard** at <http://127.0.0.1:8501>. It loads the committed
   release bundle, so no training happens on start (measured: first render 3.7 s,
   subsequent reruns 0.30 s, ten screens, no exceptions).

3. **Load network traffic.** The *Forecast* tab runs the synthetic replay
   automatically from `data/fixtures/attack_replay.csv`. The *Live* tab accepts a
   flow CSV or PCAP upload. Everything is local.

4. **Run detection.** The *Live* tab, or:

   ```bash
   KEY=your-key   # demo mode also accepts sent_demo_key_2026
   curl -s -X POST http://127.0.0.1:8100/v1/detect \
     -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
     -d "$(uv run python -c '
   import json
   from sentinel.ingestion import read_flow_csv
   ev = list(read_flow_csv("data/fixtures/attack_replay.csv").events)
   print(json.dumps({"events": [e.model_dump(mode="json") for e in ev],
                     "window_seconds": 60, "stride_seconds": 60}))')"
   ```

   Observed on the committed fixture: **36 windows, 19 alerts** across
   `reconnaissance`, `credential_abuse`, `lateral_movement`, `ddos` and
   `insider_threat`.

5. **View the attack-stage assessment.** `POST /v1/forecast` on the same events,
   or the *Forecast* tab. Observed: stage **`Lateral Movement`** with
   `MITRE ATT&CK Enterprise TA0008`.

6. **Inspect risk and explanation.** The forecast response carries the
   probability timeline, a conformal interval, and the driving features. Observed
   top drivers: `packets_max +3.66`, `packets_mean +2.11`,
   `flag_psh_ratio +1.68`. The console labels every panel **observed** vs
   **forecast**.

7. **Inspect evidence and alert history.** The *Trust ledger* panel on the
   *Forecast* tab: press **Record alert**, then read the integrity stat. The
   chain is a hash chain over forecast and evidence metadata — no raw traffic is
   written — and `verify()` re-hashes every record and every link on read.

8. **Optional: demonstrate the caveat.** Say the open-loop skill is ~0. The
   *Forecast* tab shows the warnings the forecast emits, including "Packet
   features are unavailable" for a flow-only capture and "baseline-only decay
   estimate" when no temporal model is supplied. That honesty is the point.

**Fallback if the dashboard is slow to start:** `uv run python
scripts/smoke_demo.py` runs the same seven steps headless and prints the measured
value for each. It exits non-zero on the first failure.

**Demo mode.** On by default so nothing above needs setup. The API accepts the
published key `sent_demo_key_2026` only while `SENTINEL_DEMO_MODE=true`, and
`/health` reports `"demo_mode": true`. With demo mode off the app refuses to
start without a real key and rejects the published one. See
[.env.example](.env.example).

## Honest Limitations

- **This is a research prototype, not a production SOC platform.** It is a
  prototype demonstrating predictive forecasting.
- Synthetic replay validates pipeline behaviour, not production detection
  performance. The first synthetic corpus was trivially separable; the current
  one is deliberately harder and the headline numbers are lower because of it
  (see *What's Measured*).
- **Lateral movement and exfiltration are capped sub-alert** without a
  per-deployment benign baseline, which is not implemented. The absolute byte
  band they fall back to over-fires on real traffic, and the warning on every
  finding says so.
- Three of the nine detector rules are disabled without DNS or EDR telemetry, so
  six of nine are exercised by this dataset.
- World-model open-loop skill is measured on synthetic replay only. It degrades with horizon and no horizon is free
- **Measured median forecast lead time is 0.0 windows** on both the default and the calibrated threshold. Nothing in this project fires before an attack starts on this dataset, and that is a property of the generator, not of the architecture. The calibrated threshold buys a higher crossing rate at a much higher false-early rate; the trade is recorded, not resolved
- The linear transition baseline cannot simulate: its one-step map is expansive, so the stability projection flattens it into a near-constant predictor. **The world model's open-loop comparison against it is therefore not like-for-like** — and on the current corpus the world model's own margin over persistence is small and not robust to how it is measured (+0.060 over five steps, -0.001 over the bundle's three-step test metric). The "beats persistence" claim is withdrawn. See `docs/KNOWN_LIMITATIONS.md`
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
