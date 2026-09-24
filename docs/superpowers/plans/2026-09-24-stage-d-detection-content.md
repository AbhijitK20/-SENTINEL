# Stage D: Detection-as-Code and Ingestion Quality Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Run after Stage A coverage semantics are stable.

**Goal:** Apply the reference SOC lab’s detection-as-code discipline to SENTINEL’s existing supported network/auth/DNS telemetry, with tested rules and clear telemetry gaps.

**Architecture:** Keep detectors as native Python over `NetworkState`/`UnifiedEvent`. Add small fixture-backed behavioral tests and telemetry provenance rather than importing Wazuh, Suricata runtime, Sigma’s incomplete test evaluator, or a second log-ingestion framework.

**Tech Stack:** Existing Python detector/ingestion modules, pytest fixtures, Ruff; no new dependency.

**Spec:** `docs/superpowers/specs/2026-09-24-research-to-sentinel-design.md`

## Global Constraints

- Each detection has a malicious positive fixture and benign negative fixture.
- Rules only fire when required telemetry is present; missing telemetry produces an explicit warning/unknown state.
- Offline-first runtime and existing leakage guards remain unchanged.
- Version detector behavior when thresholds or semantics change.

---

### Task 1: Audit telemetry coverage and fixture formats

**Files:**
- Read: `src/sentinel/telemetry.py`, `src/sentinel/pcap_ingestion.py`, `src/sentinel/state_builder.py`
- Test: `tests/test_telemetry.py`, `tests/test_pcap_ingestion.py`, `tests/test_state_builder.py`

- [ ] List fields actually emitted by each parser and state-builder coverage flags.
- [ ] Add no new parser until an input format and representative benign/malicious fixtures are specified.
- [ ] Record unavailable email/process/DNS-name/identity signals as unavailable instead of inferring them from generic flow data.

### Task 2: Correct DNS entropy to operate on DNS labels

**Files:**
- Modify: `src/sentinel/telemetry.py` only if documented DNS stub parsing can preserve a query label safely
- Modify: `src/sentinel/detectors.py`
- Test: `tests/test_detectors.py`
- Test: `tests/test_telemetry.py`

- [ ] Test entropy for repeated low-entropy labels, random high-entropy labels, short labels, and absent query-name telemetry.
- [ ] Calculate Shannon entropy over characters of actual query labels; do not hash endpoint strings or use Python `hash()` (process-randomized and unrelated to DNS entropy).
- [ ] Compare with per-source benign history when enough observations exist; otherwise return explicit insufficient-baseline warning and no alert.
- [ ] Keep this finding separate from generic reconnaissance unless an evidence-based ATT&CK mapping and contract semantics justify the classification.

### Task 3: Add native detection fixtures from applicable SOC rules

**Files:**
- Modify: `src/sentinel/detectors.py` only for patterns represented in supported telemetry
- Test: `tests/test_detectors.py`
- Modify: `docs/DATA_CONTRACTS.md` if source/feature requirements are newly documented

- [ ] Select only network/auth rules supported by existing data: scan fanout/probe, failed-auth burst, DNS tunneling if query names exist.
- [ ] For each rule, add one positive and at least one benign negative test.
- [ ] If a Sigma rule needs endpoint process events, email headers, or packet payload data not represented in SENTINEL contracts, document it as out-of-scope instead of simulating evidence.
- [ ] Bump detector version and keep old artifact behavior either explicitly supported or rejected with a clear error.

### Task 4: Verify detector content lifecycle

**Files:**
- Modify: tests only unless the repository already has a rule-validation CLI suitable for extension.

- [ ] Ensure every implemented rule’s MITRE ID is known and its telemetry requirement is declared.
- [ ] Run focused detector tests, then full project gate.
- [ ] Do not add auto-blocking; keep recommendations advisory.
