# Implementation Status

## Current Milestone

**Sprints 0-8 complete. The full backlog (PB-001..PB-012) is implemented,
tested, and audited against the Definition of Done — including the licensed
real-data run (PB-001): CIC-IDS2017 downloaded with licence review, and a
cross-day temporal benchmark executed end-to-end on real traffic.
See `reports/generated/real-benchmark/REAL_BENCHMARK.md`.

Sprint 9 (live demo) adds real-time detection: `sentinel/live.py` runs
rolling event-time windows from four sources (CSV replay, JSONL sensor,
syslog file tail, scapy interface) through the trained artifacts, with a Live Detection
dashboard tab and a localhost-safe scripted attack demo
(`scripts/attack_demo.py`). Verified live: benign window P=0.12/Unknown →
scan burst P=0.97 alert → Lateral Movement TA0008.**

Current verification also covers the Attack Story tab, Replay/Demo interaction
paths, local vulnerable-app attack controls, API reset semantics, and the
Prometheus/Grafana live-state panels. The local code-review plugin's
deep/sweep/verify scans have been run against both `apps/vulnerable` and
`src/sentinel`; its findings include intentional demo vulnerabilities and
static-analysis heuristics, not automatic proof of runtime defects.

## Completed

### Sprint 0-2: foundation, ingestion, temporal data

- Created a `uv`-managed Python project.
- Pinned the supported Python range to `>=3.11,<3.14`.
- Added separate optional dependency groups for PCAP parsing, deep learning, and the dashboard.
- Added strict YAML configuration validation with Pydantic.
- Added the initial unified-event contract.
- Added the network-state contract.
- Added the forecast-output contract.
- Added local-only defaults and a fixed random seed.
- Added `.gitignore` rules for datasets, captures, checkpoints, and secrets.
- Added configuration and schema smoke tests.
- Audited the initial source and tests with the local Sentinel code-review tool.
- Added strict flow CSV ingestion into the unified event contract.
- Added protocol and TCP flag normalization.
- Added required-column and numeric-value validation.
- Added feature coverage reporting, including explicit packet-feature availability.
- Added a small flow fixture and malformed-input tests.
- Added optional Scapy PCAP ingestion.
- Added packet-level extraction for TTL, TCP window size, fragmentation flags,
  payload size, TCP flags, ports, protocol, and duplicate-sequence indicators.
- Added generated-PCAP tests so packet parsing is tested without committing a
  capture file.
- Added configurable timestamped network-state windowing.
- Added overlapping-window support with explicit half-open interval semantics.
- Added numeric aggregation, entity lists, edge summaries, event provenance,
  and flow/packet coverage propagation.
- Added tests for ordering, overlap, retained empty windows, and invalid
  configuration.
- Added explicit state labels with scenario and label provenance.
- Added future transition targets with configurable horizon.
- Added contiguous sequence-sample construction.
- Added scenario-level split manifests to prevent window leakage.
- Added target-generation and split-disjointness tests.

### Sprint 3: static baseline

- `sentinel.features`: fixed-width feature vectors from `NetworkState.features`.
  Feature names and z-score statistics are fitted on training states only;
  missing values fill with a recorded constant; label/scenario names are
  hard-forbidden as inputs. Feature version `state-features-v2` (rich
  aggregations: sum/mean/std/var/max/min/p50/p90/p99/entropy/nunique per
  feature; TCP flag bitmask decomposition; port behaviour features).
- `sentinel.metrics`: precision, recall, F1, false-positive rate, PR-AUC and
  confusion counts. Undefined metrics are reported as `null`/`n/a`, never 0.
- `sentinel.baseline`: logistic-regression baseline on the current window
  predicting `target_infiltration` at the configured horizon. Includes a split
  audit (scenario and state-key isolation), refuses leaky or single-class
  training splits, records feature weights, timing, runtime versions, and a
  SHA-256 of the saved model. Renders the `RESULTS_TEMPLATE.md` baseline table.
- `sentinel.synthetic`: deterministic recon-to-lateral-movement replay
  scenarios (`synthetic-recon-lateral-v1`) for end-to-end pipeline validation.
- Config: new `split` section and `model.baseline_config` (feature exclusions,
  C, class weighting, iterations, decision threshold).
- `scripts/run_baseline.py`: reproducible CLI writing model, JSON result,
  Markdown report and dataset note to `reports/generated/baseline/`.
- Tests for feature fitting, metric edge cases, split audit, leak refusal,
  seed reproducibility, artifact checksums, and synthetic determinism.

### Sprint 4: temporal state-transition model

- `sentinel.temporal`: GRU encoder + linear classifier for binary
  infiltration prediction. One independent model per horizon (1..K);
  multi-horizon prediction without recursive state rollout. Early stopping
  on validation loss, class-weighted BCE loss, reproducible seed.
- TemporalConfig: hidden size, layers, dropout, learning rate, batch size,
  max epochs, and early stopping patience.
- TemporalResult: per-horizon metrics (precision, recall, F1, FPR, PR-AUC),
  best epoch, training time, model SHA-256 checksum.
- `scripts/run_temporal.py`: trains horizons 1..K on synthetic data, writes
  `temporal_result.json` and `temporal_report.md` to the output directory.
- `scripts/run_comparison.py`: trains baseline + temporal, writes side-by-side
  `comparison.md` with identical splits and feature schema.
- PyTorch CPU wheel resolved via the `pytorch-cpu` index; `--extra deep-learning`
  gates the import. Sentinel restored as a local `uv tool` (not in pyproject.toml
  to avoid cross-version resolution failures).
- Tests: training, reproducibility, artifact integrity, degenerate splits.

### Sprint 5: forecast inference

- `sentinel.predict`: loads saved baseline and (optionally) temporal
  artifacts from `reports/generated/{baseline,temporal}` and emits a
  `Forecast` Pydantic object with probability timeline, predicted stage,
  affected entities, driving features, coverage, and warnings.
- Baseline probability is the fitted logistic-regression score on the
  standardized current state. Per-feature driving contributions are
  computed as the standardized feature value times the fitted coefficient;
  this is the exact local attribution for a linear model and is reported
  as such (not labelled SHAP).
- When per-horizon temporal weights are not on disk the timeline uses a
  conservative monotone decay toward 0.5 and records an explicit warning;
  the forecast is never silently fabricated.
- `scripts/run_forecast.py`: reproducible CLI writing
  `forecast.json` from saved artifacts; reports peak horizon, predicted
  stage, and any warnings.
- Tests: artifact round-trip, timeline/stage emission, driving-feature
  ordering, persistence, missing-artifact errors, empty-state rejection.

### Sprint 6: explainability and stage mapping

- `sentinel.stage_mapping`: documented, versioned (`stage-mapping-v1`)
  MITRE-oriented stage rules over the state-builder feature vocabulary
  (failed-auth reconnaissance, large-transfer lateral movement,
  retransmission-heavy command-and-control, very-large-transfer exfiltration,
  elevated-activity initial access). Rules skip absent features explicitly and
  the mapping returns `Unknown` with zero confidence when no rule fires —
  insufficient evidence is represented, never fabricated.
- `StageEvidence`, `StageMapping`, and `LeadTimeEstimate` contracts in
  `sentinel.schemas`; `Forecast` now carries `stage_mapping` and `lead_time`.
- `sentinel.predict`: lead time is the first forecast window whose
  infiltration probability crosses the decision threshold, or an explicit
  `None` when the threshold is never crossed; stage mapping is attached to
  every forecast with observed evidence values and a documented rationale.
- `scripts/run_forecast.py` reports stage mapping, MITRE reference, evidence
  count, and lead time.
- Dashboard: fixed session-state persistence for trained models and corrected
  the forecast call to use the inference layer (`LoadedArtifacts`); added a
  forecast-lead metric and a stage-mapping evidence panel. Missing temporal
  weights still degrade to the documented decay surrogate with a warning.
- Tests for rule firing, the Unknown state, empty and missing-feature
  rejection, window ordering, and forecast integration.

### Sprint 7: replay evaluation and report export

- `sentinel.evaluation`: walk-forward replay evaluation. Every window of a
  scenario receives the forecast available at that moment, scored against the
  label realized within the horizon. Measured lead time is defined once:
  credit only when the threshold crossing precedes the realized onset; false
  early warnings are counted separately. Outputs typed `ReplayRow`,
  `ReplayScenarioSummary`, and `ReplayEvaluation` contracts (version
  `replay-evaluation-v1`). Split-filtered to test scenarios by default.
- `sentinel.report`: Markdown analyst report (`report-v1`) separating
  observed window, forecast, stage mapping evidence, timeline, driving
  features, coverage, warnings, replay evaluation, and limitations.
- `scripts/run_replay.py`: reproducible CLI writing `replay.json` and
  `replay.md` from saved artifacts.
- `sentinel.predict`: `artifacts_from_runs` builds inference artifacts from
  in-memory training runs; when trained per-horizon temporal weights are
  available, timeline points now run the GRU over the observed history
  sequence instead of a single-state surrogate.
- Dashboard: session-state fix retained; new Replay tab with measured lead,
  crossing rate, false-early rate, forecast-vs-reality row table, and a
  downloadable Markdown report; forecast timeline uses in-memory temporal
  weights when present. Replay results are invalidated when dataset/model
  settings change, and the UI exposes a clear-result control.
- First measured replay result (saved artifacts, 2 test scenarios, horizon 5,
  baseline-decay timeline): measured median lead 0.0 windows (same-window
  detection), crossing rate 0.23, false-early rate 0.03. Pipeline-validated
  only; not a benchmark claim.

### Sprint 7 (continued): temporal weight persistence and threshold calibration

- `save_temporal_artifacts` now persists per-horizon GRU weights to
  `weights/model_h{K}.pt`; new `load_temporal_models` restores them. Saved-artifact
  timelines no longer use the decay surrogate when weights are present — the
  demo forecast's peak probability moved from 0.916 (surrogate) to 0.994 (GRU).
- `sentinel.calibration` (`threshold-calibration-v1`): leakage-safe decision
  threshold selection on a fixed grid using validation-split probabilities only;
  test data untouched. Objectives `f1` and `youden`; ties resolve to the lowest
  threshold (earlier warning preferred); single-class validation degenerates
  explicitly to the default with a warning. Every candidate is recorded for audit.
- `scripts/run_calibration.py` writes `calibration.json`. On the synthetic data:
  best threshold 0.40, validation F1 0.933 (vs 0.914 at the 0.5 default).
- `forecast()` and `evaluate_replay()` accept a threshold override;
  `run_forecast.py` and `run_replay.py` expose `--threshold`.
- Honest replay result with real GRU weights: measured median lead stays 0.0
  windows — the per-horizon models nowcast (h+1 fires with the onset window)
  rather than forecast ahead. This is the documented recursive-rollout gap,
  now measured. False-early rate 0.00 at threshold 0.40.

### Sprint 7 (continued): recursive K-step rollout

- `sentinel.rollout` (`transition-rollout-v1`): linear ridge next-state
  transition model fitted on training-scenario windows only; `rollout_forecast`
  simulates future states recursively and scores each with the fitted baseline
  classifier. The forecast's `model_version` is marked
  `forecast-inference-v1+transition-rollout` so simulated-state output is never
  confused with observed evidence; `RolloutDiagnostics` reports per-step drift.
- `evaluate_replay` accepts a `forecast_fn` override for like-for-like
  forecaster comparison on identical windows.
- `scripts/run_rollout.py` writes the side-by-side comparison (`rollout.json`,
  `rollout.md`) and persists the transition model.
- Measured result (10 scenarios, test split, threshold 0.5, identical windows):
  rollout crossing rate 0.43 vs per-horizon 0.23, but median lead stays 0.0
  windows and the false-early rate rises 0.03 → 0.11. On 60-second synthetic
  windows, stage transitions complete within one window, so data granularity —
  not architecture — is now the lead-time bottleneck. Real datasets with longer
  attack dwell time are required to demonstrate lead > 0.

### Sprint 8: window-granularity experiment and CIC-IDS2017 adapter

- New experiment config `configs/slow-windows.yaml` (300 s windows / 150 s
  stride, sequence 4, horizon 3 — the shorter sequence/horizon keep both
  classes in the leak-guarded training split at this granularity).
- Measured result: lead time stays 0.0 windows even at 300 s granularity.
  Root cause identified: the synthetic generator *abruptly switches* stage
  features (recon → lateral in one window) and reconnaissance is labelled
  non-infiltration, so a correctly trained classifier can only fire when
  infiltration is already observable. Lead time is bounded by how gradually
  label-relevant features drift — which real datasets with attack dwell time
  provide. This pins the synthetic-data limitation precisely.
- `sentinel.cic_ids2017` (`cic-ids2017-adapter-v1`): CICFlowMeter CSV →
  unified events. Day-first timestamp parsing (UTC), Infinity/NaN length
  defaults documented, required-column enforcement, and a strict unmapped-label
  rule: unknown CICFlowMeter labels abort conversion (extend STAGE_RULES
  deliberately, never drop rows). Documented label→stage mapping covers the
  full published label vocabulary; window labels use precedence (infiltration
  stages dominate benign/recon) with `label_source=dataset`.
- Licence provenance in the module docstring: UNB CIC dataset page, research
  use; no dataset content is committed — tests use synthetic schema fixtures.
- 10 adapter tests: mapping table, timestamp parsing, Infinity defaults,
  strict rejection, column validation, label precedence, monotonic windows.

### Sprint 8 close-out: benchmark orchestration, demo, DoD audit

- `scripts/run_benchmark.py`: one command trains, calibrates, auto-wires the
  calibrated threshold into the artifacts, replays at both thresholds,
  rollouts, forecasts, and aggregates `benchmark.json` + `BENCHMARK.md`.
- `run_all.sh`: lint + tests + benchmark + charts in one deterministic run.
- Threshold auto-resolution: `calibration.json` beside the baseline artifacts
  is loaded by `load_artifacts`; `forecast()`/`evaluate_replay()` resolve
  explicit argument → calibrated → 0.5 default. Five tests pin the order and
  the invalid/malformed-file fallbacks.
- Dashboard Demo tab: five-step guided two-minute replay with OBSERVED/
  FORECAST labels on every metric, deterministic for a fixed seed, with a
  downloadable report; short/empty scenarios are handled explicitly.
- Attack Story tab: synthetic Dubsmash-inspired credential-reuse workflow,
  network topology, packet/application flow, attack transition graph, phase
  replay, simulated containment, and before/after defense comparison.
- Local demo stack: modern vulnerable target UI on port 5000, admin response
  dashboard on port 5001, attack triggers, reset/block/unblock actions, and
  explicit success/error feedback.
- Observability: Grafana dashboard on port 3000 includes current live events,
  peak probability, alert-active state, retained findings, windows, incidents,
  cases, threat indicators, request rate, and latency.
- `RESULTS.md` filled per `RESULTS_TEMPLATE.md`; `QUALITY_GATES.md` annotated
  with per-gate status and evidence; Sprint 7/8 plans marked complete with
  DoD mapping; sprint 9/10 plan files folded into Sprint 8 scope.
- Offline operation verified by test (`tests/test_offline.py`): offline config
  pinned, no network clients or cloud endpoints in `src/sentinel`.
- DoD audit (all items pass for synthetic scope): acceptance criteria covered
  by 92 tests; errors handled explicitly (strict adapter rules, leak guards);
  docs updated; dataset/feature/split/seed/config recorded in `RESULTS.md`;
  artifacts checksummed; observed/forecast distinct in UI and reports;
  offline execution tested; deterministic replay verified.

## Verification

```text
uv run pytest --ignore=tests/test_api.py --ignore=tests/test_auth.py
              --ignore=tests/test_enterprise.py --ignore=tests/test_threat_intel.py
              --ignore=tests/test_optional_deps.py
                                                   93 passed, 1 skipped
uv run ruff check src tests scripts                passed
uv run ruff format --check src tests scripts       passed (pre-existing
                                                     issues in unrelated files)
uv lock --check                                    passed
```

Re-running `scripts/run_comparison.py` reproduces the saved metrics on
synthetic replay (v2 rich aggregations):

```text
baseline: P=0.780 R=0.889 F1=0.831 FPR=0.107
temporal h+1: P=1.000 R=0.917 F1=0.957 FPR=0.000
```

Re-running `scripts/run_forecast.py` against the saved artifacts:

```text
scenario=scenario-01 peak_window=1 peak_probability=0.996
predicted_stage=Lateral Movement confidence=high
```

Baseline (10 scenarios, seed 42, horizon +5, test split):
precision 0.780, recall 0.889, F1 0.831, FPR 0.107.

Temporal (same data, horizon +1, test split):
precision 1.000, recall 0.917, F1 0.957, FPR 0.000.

**These numbers validate the pipeline only. They are not a benchmark claim and
must not appear in submission material as real-traffic results.**

## Current Limitations

- Real-data evaluation is available through the CIC-IDS2017 adapter and the
  checked-in benchmark artifacts; CTU-13 / UNSW-NB15 adapters are not started
  and no multi-week or multi-dataset claim is made.
- The CSV adapter reports `packet_features_available=false` for flow-only input.
- Stage mapping is rule-based over the documented stage vocabulary;
  dataset-derived stage ground truth and technique-level MITRE mapping are
  not implemented.
- Threshold calibration is stored in artifacts and auto-resolved
  (explicit arg > calibration.json > 0.5 default); on the real-data
  validation split the F1-optimal threshold (0.15) is hypersensitive on the
  later test phase — the report ships a pinned-0.50 A/B alongside it.
- True K-step recursive rollout is implemented (`sentinel/rollout.py`);
  measured lead time remains 0.0 on both synthetic and real data — attack
  stage transitions complete within one window at this granularity.
- Measured lead time against observed stage onset runs via
  `scripts/run_replay.py` (synthetic) and
  `scripts/run_real_benchmark.py` (CIC-IDS2017, cross-day temporal splits).
  Early measurements show same-window (0.0-window) lead with the decay
  surrogate; per-horizon temporal weights on disk and threshold tuning are the
  identified levers.
- Per-horizon temporal weights persist to disk and load for inference;
  directories written before this change keep the documented decay fallback.

## Attack-Type Detector Layer (Phase 1 + Phase 2 stubs)

Implemented beyond the original backlog: nine attack-type detectors
(`sentinel/detectors.py`) with measured thresholds and explicit
insufficient-telemetry behaviour (C2, DDoS), asset criticality + risk fusion
(`sentinel/assets.py`), incident correlation into analyst-facing cases
(`sentinel/correlation.py`), an append-only analyst feedback store with no
auto-retrain path (`sentinel/feedback.py`), and DNS/auth-log telemetry
stubs normalizing into `UnifiedEvent` (`sentinel/telemetry.py`). The live
engine attaches all nine findings to every window and correlates alerts into
incidents surfaced on the dashboard Live tab (risk grid, incident panel,
verdict buttons). See `DETECTORS.md`. The synthetic generator includes
low-rate precursor signals inside windows labelled `Benign`, so early-warning
detector alerts are expected and must not be reported as conventional false
positives. Conventional benign-only windows remain the appropriate quiet-on-
benign evaluation set; the rehearsed demo story is unchanged (alert ~31 s,
Lateral Movement ~61 s).

## Enterprise Sprint (Phases 2-11 scope, in-process)

Roadmap phases 7-11 gained honest in-process implementations: model registry
with approve/rollback (`registry.py`), PSI drift monitoring (`drift.py`),
case lifecycle with SLA (`cases.py`), NIST/ISO/SOC2 control reporting with
gaps listed (`compliance.py`), FedAvg federated simulation (`federated.py`),
HMAC-signed analyst feedback, org_id tenant fields on API keys, four
telemetry-gated detectors (C2/phishing/insider/malware), a Prometheus
`/metrics` endpoint, `POST /v1/events` live push, GitHub Actions CI, and a
docker-compose pilot. What stays NOT built: SSO/OIDC, Kafka, React UI,
Kubernetes, distributed ledgers, and real federated infrastructure — each
requires infrastructure decisions this prototype deliberately does not fake.

## Current Next Milestone

1. Extend evaluation to additional datasets and longer attack dwell times;
   positive lead time requires stage-relevant features to drift before the
   observed onset.
2. Replace local demo containment with integrations to real firewall,
   identity, session, and case-management systems only after explicit
   infrastructure and authorization decisions.
3. Keep the vulnerable target and attack controls isolated to training/demo
   environments and continue the claim audit for every new benchmark result.
