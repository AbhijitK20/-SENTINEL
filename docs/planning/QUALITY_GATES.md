# Quality Gates

## Gate 1: Planning Complete — PASSED

Requirements, stories, backlog, architecture direction, data plan, and acceptance criteria are linked.

Evidence: `MASTER_PROJECT_DOCUMENT.md`, `REQUIREMENTS.md`, `PRODUCT_BACKLOG.md`, `ARCHITECTURE.md`, `DATASET_PLAN.md`.

## Gate 2: Data Ready — PASSED (synthetic), REAL DATA PENDING

Feature coverage, label provenance, contracts, dataset version, and leakage controls are documented and validated.

Evidence: `DATA_CONTRACTS.md`, split manifests with disjointness audits (`trajectory.targets`, `trajectory.baseline.audit_split`), scenario-level splits tested against leakage. Synthetic dataset `synthetic-recon-lateral-v1` fully governed; CIC-IDS2017 adapter implemented and fixture-tested, real-data acquisition/licence review still open (`PRODUCT_BACKLOG.md` PB-001).

## Gate 3: Baseline Ready — PASSED

Logistic regression runs reproducibly and produces the agreed metrics.

Evidence: `RESULTS.md` baseline table (test F1 0.816, PR-AUC 0.926, seed 42), checksummed artifacts, `scripts/run_benchmark.py` reproducibility.

## Gate 4: Forecasting Ready — PASSED

Temporal model performs a genuine K-step rollout with a probability timeline. A static classifier alone cannot pass this gate.

Evidence: GRU per-horizon models (F1 0.923 at h+5) **plus** `trajectory.rollout` recursive next-state simulation with classifier-scored simulated windows — a static classifier cannot produce either. Measured lead time is honestly reported as 0.0 windows on synthetic data with the root cause documented (`RESULTS.md`).

## Gate 5: Explainability Ready — PASSED

Each forecast includes evidence or a clear unavailable/uncertain status.

Evidence: every `Forecast` carries `driving_features`, a versioned `stage_mapping` (`stage-mapping-v1`, MITRE-oriented, explicit `Unknown` state), `coverage`, and `warnings`; attribution is labelled as model evidence, never causality.

## Gate 6: Demo Ready — PASSED

Offline replay is repeatable, observed and predicted states are distinct, and the main story fits two minutes.

Evidence: deterministic seeded replay; Demo tab's five guided steps with OBSERVED/FORECAST labels on every metric; offline operation verified by `tests/test_offline.py`.

## Gate 7: Submission Ready — CONDITIONALLY PASSED

Final metrics, limitations, source link, README, architecture document, video script, and five-slide outline are internally consistent.

Evidence: `RESULTS.md` and `reports/generated/benchmark/BENCHMARK.md` use identical numbers with an explicit claim-status banner; `KNOWN_LIMITATIONS.md` and every report state the synthetic-data scope.

Outstanding before submission: the two-minute demo video recording, the licensed real-data run (or an explicit scope statement in the submission), and a final cross-document claim audit pass.
