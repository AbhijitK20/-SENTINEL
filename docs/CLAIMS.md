# Claims and their evidence

Every capability claim in this repository, mapped to the test that proves it and
the artifact the number came from. A claim with no artifact is not a result; it
is a target.

The rule this file exists to enforce: **a number goes in a document only if a
script in this repository printed it, and the output is either committed or one
command away.** Where that is not true, the row says so.

Last audited: 2026-09-27, against commit `0c76118`.

## How to re-verify everything in this file

```bash
make gate                    # lint, format, full test suite, release verification
make demo-path               # the six-beat golden path, no clicking
make bench-detectors         # per-rule precision/recall/F1
make bench-backtest          # rolling-origin retraining
make bench-world             # world-model open-loop skill
make verify                  # committed release bundle against its manifest
```

## Backed by a test and a committed artifact

| Claim | Test | Artifact | Notes |
|---|---|---|---|
| The release bundle matches its manifest | `make verify` (`scripts/verify_release_artifacts.py`) | `models/release/v1/` (18 files + manifest) | enforced in CI as the `release` job |
| Every forecast carries a real explanation | `tests/test_explain_service.py` | - | exact Shapley for linear, integrated gradients for the world model |
| Attributions sum to the logit | `test_exact_values_sum_to_the_logit` | - | additivity verified, not asserted |
| An unsupported explanation method raises | `test_unsupported_method_raises_instead_of_faking` | - | the fabricated `kernel` method is gone |
| Confidence varies per window | `tests/test_predict.py` | - | was a constant PR-AUC before |
| No measurement means zero confidence | `test_no_measurement_means_zero_confidence` | - | not an invented middle value |
| A rolling-origin fold never trains itself | `tests/test_backtest.py` | - | layout, not metrics |
| A stale artifact bundle is skipped, not fatal | `tests/test_dashboard_artifacts.py` | - | |
| The console opens on the shipped bundle | `test_the_console_renders_from_the_bundle_without_training` | `models/release/v1/` | 6.7s, no in-session training |
| The golden path runs in one command | `scripts/demo_script.py` | - | also the CI smoke test |
| A v2 transition artifact fails loudly | `tests/test_rollout.py` | - | load-bearing version strings |
| Undefined detector rates are `None`, not `0.0` | `tests/test_detector_benchmark.py` | - | |
| The temporal model is a GRU and has no attention | `src/sentinel/explain/__init__.py` | - | the field is never populated |

## Backed by a test, numbers produced by a script this session

All **synthetic** data unless stated otherwise. Reproduce with the command; the
numbers will differ by seed, and that is the point - they are not constants.

| Claim | Command | Measured |
|---|---|---|
| Rolling-origin direction accuracy holds flat | `make bench-backtest` | 0.91 mean over 4 origins; the calibrated threshold swings 0.25-0.85 |
| The lateral-movement rule is close to noise | `make bench-detectors` | precision 0.194, recall 0.259, F1 0.222 (7 TP / 29 FP / 20 FN) |
| The reconnaissance rule is usable but noisy | `make bench-detectors` | precision 0.686, recall 1.000, F1 0.814 (24 TP / 11 FP / 0 FN) |
| Seven of nine rules cannot be scored here | `make bench-detectors` | reported as not evaluable, with the reason |
| The linear transition baseline is barely a simulator | `make bench-world` | pre-projection spectral norm ~1.6e5; the projection keeps ~6e-06 of it |
| The imagined-risk calibration term makes things worse | see `docs/KNOWN_LIMITATIONS.md` | bias +0.099 -> +0.122, Brier 0.0815 -> 0.0854 over 56 cuts |
| The world model beats persistence open-loop | `make bench-world` | +0.189 mean skill |

## Not currently backed by an artifact - treat as unverified

These claims appear in the documentation and **cannot be reproduced from this
repository as it stands**. They are not asserted to be false; they are asserted
to be unbacked, which for a results table is the same thing.

| Claim | Where | Why unbacked | What would fix it |
|---|---|---|---|
| A cross-day CIC-IDS2017 forecast benchmark was executed on real traffic, with a lead-time and false-early table | `docs/RESULTS.md` | `reports/generated/real-benchmark/` does not exist in the repo and no CIC-IDS2017 CSV is present; `data/raw/` holds only `fixture-lab`, which is a synthetic file this project generates | Obtain the licensed CSVs, place them in `data/raw/cic-ids2017/TrafficLabelling/`, run `make bench-real`, and commit the report |
| ~900k real flows were benchmarked | `deliverables/ABSTRACT.md` | same | same |
| PB-001 "Confirm dataset availability and licenses" is Done | `docs/planning/PRODUCT_BACKLOG.md` | no dataset is present | same |
| Sprint 0-8 complete including the licensed real-data run | `docs/IMPLEMENTATION_STATUS.md` | same | same |

## Explicitly not claimed

- No graph neural network. The GAT was deleted; only `build_network_graph` ships.
- No attention visualisation. The temporal model is a GRU and produces no
  attention weights, so `Explanation.temporal_attention` and `graph_attention`
  are always `None`.
- No field benchmark. `scripts/validate_real_detectors.py` is a plumbing check
  on a single host with log-derived features.
- No causal claim. Every attribution is model evidence.
- No posterior interval on the probability timeline. `ProbabilityPoint.confidence`
  is a per-window score composed of horizon skill, model agreement, and
  decisiveness. Nothing there is sampled.
- No like-for-like world-model-vs-linear comparison. The linear baseline is
  crushed by its own stability projection; the rollout forecast says so on its
  face.

## Version strings are load-bearing

| Version | Module |
|---|---|
| `state-features-v1` | `features.py` |
| `state-features-v4` | `state_builder.py` |
| `network-graph-v1` | `graph/state.py` |
| `world-model-rssm-v1` | `world_model/model.py` |
| `rssm-imagination-v1` | `world_model/imagine.py` |
| `file-forecast-v1` | `file_forecast.py` |
| `gru-temporal-v1` | `temporal.py` |
| `transition-rollout-v3` | `rollout.py` |
| `forecast-inference-v1` | `predict.py` |
| `stage-mapping-v1` | `stage_mapping.py` |
| `threshold-calibration-v1` | `calibration.py` |
| `replay-evaluation-v2` | `evaluation.py` |
| `detector-benchmark-v1` | `scripts/run_detector_benchmark.py` |
| `rolling-origin-backtest-v1` | `scripts/run_backtest.py` |
| `golden-path-demo-v1` | `scripts/demo_script.py` |
| `cic-ids2017-adapter-v1` | `cic_ids2017.py` |
