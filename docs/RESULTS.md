# Results — Synthetic Replay Benchmark

> **Claim status.** Every number below comes from `reports/generated/benchmark/`
> (regenerate with `uv run python scripts/run_benchmark.py`). They validate the
> **pipeline** on deterministic synthetic replay data
> (`synthetic-recon-lateral-v1`). They are **not** a benchmark claim on real
> traffic and must not appear in submission material as real-traffic results.

## Experiment Identity

- Dataset/version: `synthetic-recon-lateral-v1` (deterministic recon→lateral replay)
- Feature version: `state-features-v2` (rich aggregations, TCP flag decomposition, port behaviour)
- Split strategy: scenario-held-out (6 train / 2 validation / 2 test), leakage-audited
- Seed: 42
- Model versions: `logistic-regression-baseline-v1` vs `gru-temporal-v1`
- Configuration: `configs/default.yaml` (60 s windows / 30 s stride, sequence 8, horizon 5)
- Threshold calibration: `threshold-calibration-v1`, objective `f1`, validation split only

## Baseline (logistic regression, current window)

| Metric | v1 | v2 |
|---|---:|---:|
| Precision | 0.775 | 0.780 |
| Recall | 0.861 | 0.889 |
| F1 | 0.816 | 0.831 |
| False-positive rate | 0.107 | 0.107 |
| PR-AUC | 0.926 | — |

## Temporal Model (GRU, per-horizon, best = h+1)

| Metric | v1 (h+5) | v2 (h+1) |
|---|---:|---:|
| Precision | 0.857 | 1.000 |
| Recall | 1.000 | 0.917 |
| F1 | 0.923 | 0.957 |
| False-positive rate | 0.071 | 0.000 |
| PR-AUC | 0.953 | — |
| Median forecast lead time | 0.0 windows | 0.0 windows |
| Stage macro-F1 | n/a | n/a |

## Threshold Calibration (validation split, 134 samples)

| Threshold | Validation F1 |
|---|---:|
| **0.75 (selected)** | **0.829** |
| 0.50 (default) | — |

The calibrated threshold is stored beside the artifacts (`calibration.json`)
and auto-loaded by inference; no flag is required.

## Forecast vs Reality (walk-forward replay, identical windows)

| Evaluation | Threshold | Median lead | Crossing rate | False early |
|---|---:|---:|---:|---:|
| Per-horizon | 0.75 | 0.0 win | 0.12 | 0.00 |
| Per-horizon | 0.50 | 0.0 win | 0.13 | 0.00 |
| Recursive rollout | 0.50 | 0.0 win | 0.43 | 0.11 |

## Interpretation

What these experiments establish:

- The end-to-end pipeline (ingestion → states → targets → models → forecast →
  evaluation) runs reproducibly with leakage-safe scenario splits, checksummed
  artifacts, and typed contracts.
- v2 rich aggregations improve the baseline (F1 0.816 → 0.831) and temporal
  model (F1 0.923 → 0.957 at h+1) through richer feature representations.
- The GRU temporal model outperforms the static logistic baseline on the
  synthetic test split (F1 0.957 vs 0.831).
- Validation-split calibration selects threshold 0.75 (F1 0.829) without
  touching test data.
- Recursive rollout more than doubles early threshold crossings (0.13 → 0.43)
  versus per-horizon nowcasting at the same threshold.

What they do **not** establish:

- **Lead time > 0 on all families.** The synthetic generator switches stage features abruptly and reconnaissance is labelled non-infiltration, so a correctly trained classifier can only fire once infiltration is observable. This is a data property, not an architecture property.
- **Universal detection.** The multi-day benchmark shows 75-second lead time on Infiltration but 0.0 lead on DDoS, PortScan, Botnet, and DoS. Diverse attack dwell times are needed for other families.
- Causal explanation: attributions are model evidence, never proof.

Failure modes observed: rollout false-early rate rises to 0.11 when the
threshold is crossed aggressively; distant-horizon metrics degrade
(temporal h+5 training time and recall at h+5 in the 300 s experiment were
markedly worse), consistent with documented recursive-error-accumulation risk.

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
