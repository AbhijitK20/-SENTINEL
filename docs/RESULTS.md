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

| Metric | Test (v3) |
|---|---:|
> ### Why these numbers are much lower than earlier releases
>
> `synthetic-recon-lateral-v2` was **trivially separable**. Each phase drew from
> its own disjoint band of byte volumes, port sets, destination hosts and TCP
> flag words, so the infiltration label was recoverable from one scalar. Over 98
> features the baseline scored ROC-AUC 0.9933 on the test split while a *single*
> feature (`flag_psh_ratio`) scored 0.9861 — a gap of 0.0072. Ninety-seven of the
> ninety-eight features were decoration, and every metric above measured the
> shortcut rather than forecasting.
>
> `synthetic-recon-lateral-v3` removes the shortcut: benign traffic is a mixture
> (including bulk transfers and established PSH sessions) whose volume overlaps
> the lateral phase, destinations and ports are drawn from shared pools, phase
> lengths vary per scenario, and benign windows carry ordinary probe traffic.
> Measured on `synthetic-recon-lateral-v3` (seed 42, 10 scenarios, scenario-level
> 60/20 split, 60 s windows, 30 s stride, unchanged protocol):
>
> | | v2 (shortcut) | v3 (corrected) |
> |---|---:|---:|
> | best single-feature ROC-AUC | 0.9833 | 0.7407 |
> | full baseline ROC-AUC | 0.9933 | 0.9302 |
> | **full minus single (the gap)** | **0.0072** | **0.1126** |
> | baseline F1 | 0.892 | 0.702 |
> | baseline PR-AUC | 0.978 | 0.662 |
> | baseline FPR | 0.060 | 0.306 |
>
> The headline numbers got worse because they were measuring a shortcut. The
> number that matters is the gap: on v3 the other 97 features earn 0.113 ROC-AUC,
> where on v2 they earned 0.007. Reproduce with
> `uv run python scripts/diagnose_separability.py`, and the regression is gated by
> `tests/test_benchmark_separability.py`.
>
> This is still a synthetic benchmark. It demonstrates that the pipeline learns a
> structural signal rather than a volume shortcut; it is not evidence of
> real-world forecasting ability.


| Precision | 0.635 |
| Recall | 0.786 |
| F1 | 0.702 |
| False-positive rate | 0.306 |
| PR-AUC | 0.662 |

## Temporal Model (GRU, one independent model per horizon)

| Horizon | Precision | Recall | F1 | FPR | PR-AUC | Best epoch |
|---|---:|---:|---:|---:|---:|---:|
| h+1 | 0.745 | 0.905 | **0.817** | 0.186 | 0.885 | 7 |
| h+2 | 0.649 | 0.881 | 0.747 | 0.294 | 0.839 | 6 |
| h+3 | 0.696 | 0.762 | 0.727 | 0.212 | 0.823 | 8 |
| h+4 | 0.711 | 0.762 | 0.736 | 0.203 | 0.827 | 10 |
| h+5 | 0.674 | 0.738 | 0.705 | 0.242 | 0.800 | 9 |

Best horizon is h+1 (F1 0.817 vs baseline 0.702). Recall degrades toward h+3
and does not recover monotonically, which is why no single horizon is quoted as
"the" temporal result. The withdrawn v2 figures for this table were 0.957 at
h+1 with a 0.000 false-positive rate; those were measured on a corpus where the
label came from one scalar.


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
| **World model (RSSM + open-loop objective)** | 0.439 | 0.462 | 0.488 | 0.517 | 0.556 | **+0.060** |
| Linear ridge transition (`transition-rollout-v3`) | 0.669 | 0.670 | 0.666 | 0.666 | 0.673 | −0.298 |
| Ablation: same net, no open-loop objective | 0.538 | 0.539 | 0.563 | 0.606 | 0.660 | −0.114 |
| Persistence (repeat last window) | 0.347 | 0.524 | 0.575 | 0.607 | 0.651 | 0.000 |

These are the figures the benchmark printed for the current generator. The
withdrawn v2 table reported **+0.189** for the same model, and that separation
was the trivial-separability artefact: on v2 the label was recoverable from one
scalar, so "imagine the next state" was close to "look up the answer".

**A second, weaker number is recorded because it is in the release bundle.**
`models/release/v1/world_model.json` stores a 3-step open-loop metric on its
held-out test split giving a mean skill of **−0.001** (per step −0.282, +0.122,
+0.156). These are not the same measurement: the table above is the benchmark
harness rolling five steps across every held-out scenario; the bundle figure is
the three-step metric stored with the shipped model. A reader who checks both
will notice the gap, so it is stated here rather than left to be discovered.

The honest summary is that the world model's open-loop advantage is **small and
not robust to how it is measured**. The earlier "beats persistence" claim is
withdrawn; what survives is "beats persistence from step two onward in the
five-step harness, and does not in the bundle's three-step test metric".

Windows evaluated: 120 (2 held-out scenarios × every contiguous history/future pair).

Three things this table establishes:

1. **The learned dynamics beat the linear surrogate at every step, and beat
   persistence from +2 onward — but lose to persistence at +1.** Losing the
   first step to "repeat the last window" is worth reading carefully rather than
   skipping: at +1 the RSSM's MAE is 0.444 against persistence's 0.347.
2. **The open-loop objective is what does it.** The ablation is the identical
   architecture trained without the multi-step term. It reconstructs observed
   windows fine and still scores −0.114 once it must predict its own future —
   the exposure-bias failure, measured rather than asserted.
3. **Error grows with horizon by construction.** Recursion compounds; the
   per-step columns make that visible instead of averaging it away.

### Why the linear row loses — a measured failure mode, not a strawman

The linear model is fitted properly for this comparison, and the numbers say why
it still cannot simulate:

- Its one-step least-squares next-state map is expansive, so rolling it out
  diverges instead of forecasting. `scripts/run_world_model.py` records the
  measured norm and clip factor in `world_model_benchmark.json` for the current
  fit.
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
| lstm | 0.4110 | 0.0712 | 0.877 | 6 | +0.060 |
| gru | 0.3620 | 0.0659 | 0.852 | 6 | **+0.077** |
| transformer | 0.2818 | 0.0275 | 0.882 | 18 | +0.016 |

Reconstruction fidelity and open-loop skill move in **opposite** directions: the
transformer core reconstructs observed windows best (0.2818 vs 0.4110 MSE) and
simulates worst (+0.016 vs +0.060 for the lstm). The **gru** core is both a
better reconstructor than the lstm and the better simulator here, so the shipped
model is the lstm for historical reasons and the gru is the honest answer on
this measurement. Re-run with `--compare-cores` before changing it. Reporting only reconstruction loss would have ranked these three
in the wrong order, which is the practical argument for scoring a world model on
simulated states.

### World model split metrics (heads at observed windows)

| Split | Windows | Recon MSE | KL (nats) | Risk F1 | Risk PR-AUC | Stage macro-F1 |
|---|---:|---:|---:|---:|---:|---:|
| train | 351 | 0.4047 | 0.0645 | 0.925 | 0.990 | 0.945 |
| validation | 113 | 0.4876 | 0.0664 | 0.792 | 0.889 | 0.890 |
| test | 114 | 0.4110 | 0.0712 | 0.826 | 0.918 | 0.877 |

The KL is low (0.07 nats) because the prior — which never sees the observation —
tracks the posterior that does. That is the condition that makes open-loop
sampling a simulation rather than a decoder applied to fresh inputs.

**A low KL is necessary and not sufficient.** On the withdrawn v2 corpus this
column read 1.000 F1 and 0.005 nats on every split; those were perfect numbers
produced by a corpus whose label came from one scalar. The open-loop table above
is what shows whether the simulation is worth anything, and on the current corpus
it is a small margin. Read the two tables together, not either alone.

### Imagination forecaster in walk-forward replay

Measured on the current corpus by `scripts/run_replay.py`, whole-scenario test
split, seed 42, horizon 5. Median measured lead is **0.0 windows** on both
thresholds: nothing fires before the onset, which is a property of this
generator rather than of the architecture.

| Threshold | Median lead (win) | Crossing rate | False-early | Pre-onset warn | During-attack detect |
|---:|---:|---:|---:|---:|---:|
| 0.50 (default) | 0.0 | 0.3846 | 0.0769 | 0.2195 | 1.000 |
| 0.20 (calibrated on validation) | 0.0 | 0.8076 | 0.4615 | 0.7561 | 1.000 |

The calibrated threshold buys a much higher crossing rate at the cost of a much
higher false-early rate, and it still does not create lead time. That trade is
recorded rather than resolved.

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
- **Universal detection.** The cross-day real-traffic benchmark is PENDING (see the withdrawn section below), so no claim is made about lead time on any attack family. Diverse attack dwell times are needed before one could be.
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

## Real-Data Forecast (CIC-IDS2017) — NOT CURRENTLY REPRODUCIBLE

> **Claim status: unverified.** The table previously published here cannot be
> regenerated from this repository as it stands. `reports/generated/real-benchmark/`
> does not exist here, and no CIC-IDS2017 CSV is present — `data/raw/` contains
> only `fixture-lab/`, a synthetic file this project generates to exercise the
> adapter's column handling. Those numbers are therefore **not presented as a
> result**. They are not asserted to be false; they are asserted to be unbacked,
> which for a results table is the same thing.
>
> See `docs/CLAIMS.md`, which tracks this as an open item.
>
> **To make this real:** obtain the licensed CSVs, place them in
> `data/raw/cic-ids2017/TrafficLabelling/`, then
> `make bench-real`. Commit the generated report and this section can be restored
> with numbers that someone else can reproduce.
>
> Until then, the only forecast numbers this repository supports are the
> synthetic ones above, and `scripts/validate_real_detectors.py`'s single-host
> plumbing check, which says nothing about forecast accuracy.

### Protocol (as designed; not yet executed here)

- TRAIN: Tuesday 2017-07-04 full day (FTP/SSH-Patator)
- VALIDATION: Thursday 2017-07-06 morning (Web Attacks)
- TEST: Thursday 2017-07-06 afternoon (Infiltration 14:19-15:45)

### Results — WITHDRAWN, PENDING

<!--
The table that used to be here was removed. It was not produced by a script that
ran against data present in this repository, so it failed the project's own rule:
a number does not go in a Markdown file unless a script printed it and the output
is committed or one command away. It is recorded in docs/CLAIMS.md as an open
item. Restore it with `make bench-real` and real CSVs in place.
-->

| Threshold | Forecaster | Median lead (win) | Crossing rate | False early |
|---|---|---|---|---|
| PENDING | PENDING | PENDING | PENDING | PENDING |

### Interpretation — PENDING

No interpretation is offered, because there is no result to interpret.

### Limitations that will apply when it is run

- Two days of one capture week; the test attack family (Infiltration) never
  appears in training, which is realistic for zero-day-style evaluation but
  limits score comparability.
- Extreme class imbalance is expected (~36 attack flows against ~287k benign on
  the test day); window-level positives will be a handful of windows.
- CICFlowMeter timestamps carry the documented 12-hour defect; the adapter's
  correction should be validated against the published UNB schedule.
- Window labels derive from flow labels via documented precedence; no
  independent stage ground truth exists.
