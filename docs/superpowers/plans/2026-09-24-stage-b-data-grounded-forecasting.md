# Stage B: Data-Grounded ATT&CK Forecasting Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Run only after Stage A is complete.

**Goal:** Evaluate a reproducible, data-derived ATT&CK next-technique transition model against SENTINEL’s existing sequence detector and recursive rollout without overstating predictions.

**Architecture:** Create an offline preprocessing CLI for ATT&CK Flow/STIX sequence inputs, write a versioned transition artifact with per-edge support counts and provenance, and evaluate by scenario-level walk-forward splits. Existing forecasting remains default unless the learned model improves held-out results.

**Tech Stack:** Python stdlib JSON/CSV, existing Pydantic and evaluation modules, pytest; no LSTM dependency in this stage.

**Spec:** `docs/superpowers/specs/2026-09-24-research-to-sentinel-design.md`

## Global Constraints

- Audit the license/provenance of each input dataset before parsing or redistributing it. The prediction repository README says its own code release license is pending; do not copy its code or datasets into SENTINEL.
- Runtime `src/sentinel` remains offline; preprocessing scripts may read local files but do not fetch network data.
- Train transitions on train scenarios only, calibrate on validation only, and touch test split exactly once at final evaluation.
- Do not claim the reference repo’s reported accuracy for SENTINEL.
- Version the artifact and preserve explicit low-support/unknown-transition warnings.

---

### Task 1: Audit local ATT&CK Flow data provenance and define accepted input contract

**Files:**
- Create: `research/ATTACK_FLOW_PROVENANCE.md`
- Test: `tests/test_attack_chain_data.py`

- [ ] Check source README and per-data-file provenance/license. Mark unresolved license as unusable for checked-in artifacts.
- [ ] Define a minimal input fixture authored for tests using the STIX Attack Flow object shape; do not copy a real campaign document into tests.
- [ ] Test accepted action nodes, technique IDs, branch edges, loops, missing references, and empty sequences.
- [ ] If the cloned data lacks clear reuse rights, plan the extraction CLI to require user-supplied licensed data and leave benchmark `PENDING`.

### Task 2: Build the offline sequence extraction CLI

**Files:**
- Create: `scripts/build_attack_transition_data.py`
- Create: `src/sentinel/attack_sequences.py`
- Test: `tests/test_attack_chain_data.py`

**Interfaces:**
- `extract_sequences(bundle: dict) -> list[list[str]]`
- CLI requires `--input`, `--output`, and `--source-id`; output stores only normalized technique sequences plus provenance/version/checksum metadata.

- [ ] Write tests for STIX Attack Flow traversal before implementation.
- [ ] Traverse `attack-flow.start_refs`, `attack-action.technique_id`, `effect_refs`, and condition true/false refs with a visited set.
- [ ] Normalize only valid `Tdddd` and `Tdddd.ddd` identifiers; skip unknown/non-technique nodes without fabricating IDs.
- [ ] Write deterministic JSON with source SHA-256, ATT&CK version if present, source license label, extractor version, and sequence counts.
- [ ] Verify repeated runs on identical fixture create byte-stable content apart from deliberately excluded wall-clock timestamps.

### Task 3: Estimate smoothed transitions and support

**Files:**
- Create: `src/sentinel/attack_transitions.py`
- Test: `tests/test_attack_transitions.py`

**Interfaces:**
- `TransitionModel.from_sequences(sequences, *, smoothing, min_support, provenance) -> TransitionModel`
- `predict(sequence, *, top_k) -> list[TransitionCandidate]`

- [ ] Test exact count/probability on a tiny hand-authored sequence set, including unseen transitions and empty input.
- [ ] Store start counts and transition counts; compute row-normalized probabilities with documented additive smoothing.
- [ ] Return support count and probability with every candidate.
- [ ] Return no scored candidate for below-minimum support rather than a default estimated probability.
- [ ] Include model version and source checksum in serialized artifact.

### Task 4: Compare forecasts against existing baseline without leakage

**Files:**
- Create: `scripts/evaluate_attack_transitions.py`
- Test: `tests/test_attack_transition_evaluation.py`
- Modify: `docs/DATA_CONTRACTS.md` only if a public response is extended.

- [ ] Add tests that split by scenario/group, not individual adjacent chain prefixes.
- [ ] Compare top-1/top-k accuracy and calibration/support summaries against `sequence_detector.py` and report a confusion table.
- [ ] Keep test split untouched until model and minimum-support threshold are selected from validation.
- [ ] Print `PENDING` for metrics when no license-cleared dataset can be evaluated.
- [ ] Keep learned model opt-in; do not change `/v1/predict/next` default without held-out improvement.
