# Results — Synthetic Replay Benchmark

> **Claim status.** Every number below comes from `reports/generated/benchmark/`
> (regenerate with `uv run python scripts/run_benchmark.py`). They validate the
> **pipeline** on deterministic synthetic replay data
> (`synthetic-recon-lateral-v2`). They are **not** a benchmark claim on real
> traffic and must not appear in submission material as real-traffic results.

## Experiment Identity

- Dataset/version: `synthetic-recon-lateral-v2` (deterministic recon→lateral
  replay, flow **and** packet events, low-and-slow precursor)
- Observation: 98 features per window — flow aggregations (flag decomposition,
  port behaviour, byte/packet counters) and packet-level attributes (TTL
  spread, TCP window size, IP fragmentation, retransmissions, payload
  distribution, inter-arrival statistics)
- Feature version: `state-features-v4` state features under the
  `state-features-v1` normalization schema recorded in the artifacts
- Split strategy: scenario-held-out (6 train / 2 validation / 2 test), leakage-audited
- Seed: 42
- Model versions: `logistic-regression-baseline-v1` vs `gru-temporal-v1` vs
  `world-model-rssm-v1` vs `transition-rollout-v2`
- Configuration: `configs/default.yaml` (60 s windows / 30 s stride, sequence 8, horizon 5)
- Threshold calibration: `threshold-calibration-v1`, objective `f1`, validation split only

## Baseline (logistic regression, current window)

| Metric | Test |
|---|---:|
| Precision | 0.868 |
| Recall | 0.917 |
| F1 | 0.892 |
| False-positive rate | 0.060 |
| PR-AUC | 0.978 |

## Temporal Model (GRU, one independent model per horizon)

| Horizon | Precision | Recall | F1 | FPR | PR-AUC | Best epoch | Train ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| h+1 | 1.000 | 0.917 | **0.957** | 0.000 | 1.000 | 26 | 1151 |
| h+2 | 1.000 | 0.889 | 0.941 | 0.000 | 1.000 | 24 | 1111 |
| h+3 | 1.000 | 0.806 | 0.892 | 0.000 | 1.000 | 19 | 978 |
| h+4 | 0.909 | 0.833 | 0.870 | 0.035 | 0.985 | 16 | 812 |
| h+5 | 1.000 | 0.889 | 0.941 | 0.000 | 1.000 | 28 | 1250 |

Best horizon is h+1 (F1 0.957 vs baseline 0.892) with a zero false-positive
rate; recall degrades toward h+3 and does not recover monotonically, which is why
no single horizon is quoted as "the" temporal result.


## World Model — open-loop state prediction (the core deliverable)

> **Source.** `reports/generated/benchmark/world_model/` — regenerate with
> `uv run python scripts/run_benchmark.py` (step 7) or
> `uv run python scripts/run_world_model.py --output <dir> --baseline <baseline dir>`.
> Model `world-model-rssm-v1`, core `lstm`, hidden 64, latent 16, **98 observed
> features**, 8-window history, 5-step horizon, 32 imagination samples,
> held-out test scenarios `scenario-01` and `scenario-02`.

### Why this table and not F1

A classifier is scored on flows it is shown. A world model is scored on states it
had to **imagine**: burn in on the observed history, then roll the prior forward
with no observations and compare the decoded states with what actually happened.
Metric: mean |imagined − realized| over standardized state features.
**Skill = 1 − model MAE / persistence MAE**, where persistence repeats the last
observed window. Positive means the model beats doing nothing clever.

| Predictor | +1 | +2 | +3 | +4 | +5 | Mean skill |
|---|---:|---:|---:|---:|---:|---:|
| **World model (RSSM + open-loop objective)** | 0.305 | 0.321 | 0.348 | 0.386 | 0.433 | **+0.189** |
| Linear transition (`transition-rollout-v2`) | 0.616 | 0.616 | 0.617 | 0.619 | 0.627 | −0.429 |
| Ablation: same net, no open-loop objective | 0.482 | 0.451 | 0.452 | 0.474 | 0.513 | −0.095 |
| Persistence (repeat last window) | 0.307 | 0.451 | 0.470 | 0.487 | 0.530 | 0.000 |

Windows evaluated: 120 (2 held-out scenarios × every contiguous history/future pair).

Three things this table establishes:

1. **The learned dynamics beat both the linear surrogate and doing nothing.**
   The RSSM is better than persistence from +2 onward; the linear map is worse at
   every step.
2. **The open-loop objective is what does it.** The ablation is the identical
   architecture trained without the multi-step term. It reconstructs observed
   windows fine and still scores −0.095 once it must predict its own future —
   the exposure-bias failure, measured rather than asserted.
3. **Error grows with horizon by construction.** Recursion compounds; the
   per-step columns make that visible instead of averaging it away.

### Why the linear row loses — a measured failure mode, not a strawman

The linear model is fitted properly for this comparison, and the numbers say why
it still cannot simulate:

- Its one-step least-squares next-state map has spectral norm **2.7 × 10⁵**.
  That map is expansive, so rolling it out diverges instead of forecasting.
- It is projected to a non-expansive norm (0.98), a clip factor of 3.6 × 10⁻⁶,
  which flattens it into a near-constant predictor — visible as MAE that barely
  moves across steps (0.616 → 0.627) instead of growing.
- Its inputs are standardized before the ridge penalty; without that, a single
  `bytes_sum` column (thousands) dominates the fit.

The general result: **a one-step objective and a usable simulator are different
objectives.** A genuinely multi-step fit is not closed-form for a linear map
(unrolling is polynomial in the weights), so this prototype reports the gap
rather than hiding it. `scripts/run_world_model.py` records both norms and the
clip factor in `world_model_benchmark.json`.

### Core comparison (same objective, splits, and seed)

`uv run python scripts/run_world_model.py --output <dir> --baseline <dir> --compare-cores`

| Core | Recon MSE | KL (nats) | Stage macro-F1 | Train s | Open-loop skill |
|---|---:|---:|---:|---:|---:|
| lstm | 0.3447 | 0.0053 | 0.985 | 9 | **+0.189** |
| gru | 0.3542 | 0.0072 | 0.979 | 8 | +0.179 |
| transformer | 0.1382 | 0.0092 | 0.983 | 25 | +0.080 |

Reconstruction fidelity and open-loop skill move in **opposite** directions: the
transformer core reconstructs observed windows 2.5× better (0.138 vs 0.345) and
simulates worst. Reporting only reconstruction loss would have ranked these three
in the wrong order, which is the practical argument for scoring a world model on
simulated states.

### World model split metrics (heads at observed windows)

| Split | Windows | Recon MSE | KL (nats) | Risk F1 | Risk PR-AUC | Stage macro-F1 |
|---|---:|---:|---:|---:|---:|---:|
| train | 390 | 0.2776 | 0.0045 | 1.000 | 1.000 | 0.9997 |
| validation | 130 | 0.3562 | 0.0060 | 1.000 | 1.000 | 0.9876 |
| test | 130 | 0.3447 | 0.0053 | 1.000 | 1.000 | 0.9855 |

KL is near zero because the prior — which never sees the observation — already
predicts the posterior that does. That is the condition that makes open-loop
sampling a simulation rather than a decoder applied to fresh inputs. A low KL is
necessary, not sufficient: the open-loop table is what shows the simulation is
worth anything.

### Imagination forecaster in walk-forward replay

| Forecaster | Threshold | Median lead (win) | Pre-onset warn | Median pre-onset lead | Crossing rate | False early | During-attack detect |
|---|---:|---:|---:|---:|---:|---:|---:|
| Per-horizon (nowcast) | 0.45 | 0.0 | 0.170 | 1.0 | 0.350 | 0.067 | 1.000 |
| RSSM imagination | 0.45 | 0.0 | 0.000 | — | 0.217 | 0.000 | 1.000 |

Identical windows, threshold, and split. Two honest readings:

- The imagination forecaster detects the attack during the attack (1.00) with a
  **zero false-early rate** and a lower crossing rate than the nowcast.
- It produces **no pre-onset warning at all**. The risk head is trained on
  observed windows, so asked about a simulated precursor it regresses towards the
  prior mean. On this dataset the honest summary is that open-loop simulation
  buys auditability and quiet, not lead time; the nowcast is the one that fires
  early (median pre-onset lead 1.0 window).

## Threshold Calibration (validation split, 134 samples)

| Threshold | Validation F1 |
|---|---:|
| **0.45 (selected)** | **0.907** |
| 0.50 (default) | 0.907 |

The calibrated threshold is stored beside the artifacts (`calibration.json`)
and auto-loaded by inference; no flag is required. Selection is flat across
0.45–0.55 here, so the calibrated and default thresholds score identically on
validation.

## Forecast vs Reality (walk-forward replay, identical windows)

| Evaluation | Threshold | Median lead | Crossing rate | False early |
|---|---:|---:|---:|---:|
| Per-horizon | 0.45 | 0.0 win | 0.13 | 0.00 |
| Per-horizon | 0.50 | 0.0 win | 0.13 | 0.00 |
| Recursive rollout (linear, stabilized) | 0.50 | none | 0.00 | 0.00 |

The stabilized linear rollout crosses nothing: with a near-constant simulated
state the classifier score never reaches the threshold. Before the stability
projection the same rollout appeared to produce lead time — that number came
from an expansive map whose drift happened to cross the threshold early, which is
not a forecast anyone should rely on. It is reported here as a removed claim, not
a lost result.

## Interpretation

What these experiments establish:

- The end-to-end pipeline (ingestion → states → targets → models → forecast →
  evaluation) runs reproducibly with leakage-safe scenario splits, checksummed
  artifacts, and typed contracts.
- Both telemetry levels reach the model: 98 observed features including TTL
  spread, TCP window size, IP fragmentation, retransmissions, and payload
  distribution — the inputs the problem statement requires, and which were dead
  columns until this round.
- The GRU temporal model improves on the static logistic baseline at its best
  horizon (F1 0.957 vs 0.892) with a zero false-positive rate.
- The world model is the only component that learns a state *transition*: on
  held-out scenarios it predicts unseen future windows 19% more accurately than
  persistence, where the linear next-state surrogate scores −0.429.
- The open-loop objective, not the architecture, is what makes imagination work:
  the ablation is the same network without it and lands at −0.095.
- Reconstruction loss is a misleading model-selection signal here: it ranks the
  three cores in the reverse order of their open-loop skill.
- A file is a first-class input: `scripts/predict_file.py` takes a PCAP or flow
  CSV and returns the same `Forecast` the dashboard shows, and says so when the
  input carries no packet-level evidence.

What they do **not** establish:

- **That simulation improves alerting.** On this dataset the imagination forecaster matches during-attack detection with a lower crossing rate and never fires early; the per-horizon nowcast is the one that warns pre-onset.
- **Lead time > 0 on all families.** The synthetic generator switches stage features abruptly and reconnaissance is labelled non-infiltration, so a correctly trained classifier can only fire once infiltration is observable. This is a data property, not an architecture property.
- **That a low KL means a good world model.** KL ≈ 0.005 nats says the prior tracks the posterior; the open-loop table says how useful that is.
- **That the linear model is well fit for simulation.** A multi-step linear fit needs iterative optimisation and is not implemented.
- **Universal detection.** The multi-day benchmark shows 75-second lead time on Infiltration but 0.0 lead on DDoS, PortScan, Botnet, and DoS. Diverse attack dwell times are needed for other families.
- Causal explanation: attributions are model evidence, never proof.

Failure modes observed: open-loop error grows monotonically with horizon for
every predictor including the world model, so no horizon is free; the stabilized
linear rollout degenerates to a constant and stops alerting at all; distant-horizon
detection degrades (h+3/h+4 recall), consistent with documented
recursive-error-accumulation risk.

## Real-Traffic Detector Validation (lab)

`scripts/validate_real_detectors.py` drives the demo attack modules' real HTTP
traffic through the live path (access log → scanner → `/v1/events` →
LiveEngine) and records which detectors alert per scenario as an explicit
claimed-vs-observed matrix. Run it with the demo stack up:

```bash
docker compose --profile demo up -d --no-deps api vulnerable-app demo-sentinel
uv run python scripts/validate_real_detectors.py
```

It is a repeatable plumbing check on lab traffic, not a field measurement:
single host, known attack tools, log-derived event features, one run per
scenario. The generated report lives in
`reports/generated/real-detector-validation/` (not committed) and records
missed and unexpected firings per scenario; quote numbers only from a report
produced by the script. It says nothing about forecast-model performance on
real data, which remains unmeasured.

## Real-Data Forecast (CIC-IDS2017)

> **Claim status.** Numbers below come from
> `reports/generated/real-benchmark/REAL_BENCHMARK.md`
> (regenerate with `uv run python scripts/run_real_benchmark.py
> --data-dir data/raw/cic-ids2017/TrafficLabelling`).
> These are real-traffic results on CIC-IDS2017 with cross-day temporal splits.
> The test phase contains a single attack family (36 Infiltration flows);
> this is NOT a general performance claim.

### Protocol (strict temporal order)

- TRAIN: Tuesday 2017-07-04 full day (FTP/SSH-Patator)
- VALIDATION: Thursday 2017-07-06 morning (Web Attacks)
- TEST: Thursday 2017-07-06 afternoon (Infiltration 14:19-15:45)

### Results

| Threshold | Forecaster | Median lead (win) | Crossing rate | False early |
|---|---|---|---|---|
| 0.50 (default) | Per-horizon | **0.5** | 0.15 | 0.11 |
| 0.50 (default) | Recursive rollout | 0.0 | 0.88 | 0.58 |
| 0.05 (calibrated) | Per-horizon | 0.0 | 1.00 | 0.63 |
| 0.05 (calibrated) | Recursive rollout | 0.0 | 0.88 | 0.58 |

### Interpretation

At the default 0.50 threshold, the per-horizon model detects the Infiltration
attack 0.5 windows (75 seconds) before it fully materializes, with 11% false-early
rate. The calibrated threshold (0.05) is too aggressive — 100% crossing but 63%
false early. The recursive rollout does not improve lead time on this dataset.

### Limitations

- Two days of one capture week; the test attack family (Infiltration) never
  appears in training, which is realistic for zero-day-style evaluation but
  limits score comparability.
- Extreme class imbalance: 36 attack flows vs ~287k benign on the test day;
  window-level positives are a handful of windows.
- CICFlowMeter timestamps carry the documented 12-hour defect; the adapter's
  correction was validated against the published UNB schedule.
- Window labels derive from flow labels via documented precedence; no
  independent stage ground truth exists.
