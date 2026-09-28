# Stage C: Data-Source-Aware ATT&CK Coverage Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Run after Stage A semantics are stable.

**Goal:** Report honest detector and telemetry coverage and export the same results as a valid ATT&CK Navigator layer.

**Architecture:** Add a small offline coverage module using explicit detector metadata and configured source availability. Both API coverage and Navigator export call the same pure function. No separate SQLite rule store or second dashboard is introduced.

**Tech Stack:** Python stdlib, Pydantic schemas already present, FastAPI, pytest; no new dependency.

**Spec:** `docs/superpowers/specs/2026-09-24-research-to-sentinel-design.md`

## Global Constraints

- Runtime has no network client or ATT&CK fetch.
- Coverage dimensions remain distinct: implemented detector, telemetry present, alert observed.
- Zero-probability findings do not count as detection evidence.
- Version and document any public response changes.

---

### Task 1: Define offline detector/data-source metadata

**Files:**
- Create: `src/sentinel/coverage.py`
- Test: `tests/test_attack_coverage.py`
- Modify: `src/sentinel/detectors.py` only to expose/reuse existing attack-type-to-technique mapping.

- [ ] Read existing detector feature requirements and `NetworkState.coverage` construction.
- [ ] Define a constant metadata table for the currently supported detection techniques: technique ID, attack type, required source families, detector availability.
- [ ] Test that each entry maps to a known detector and that unavailable telemetry yields `telemetry_available=False`.
- [ ] Compute per-technique `alert_observed` only from alerting findings with positive probability.
- [ ] Compute separate detector-implemented, telemetry-available, and observed counts; do not call these an overall enterprise ATT&CK percent unless the denominator is explicitly scoped to the supported subset.

### Task 2: Build weighted coverage using source quality

**Files:**
- Modify: `src/sentinel/coverage.py`
- Test: `tests/test_attack_coverage.py`
- Modify: `configs/default.yaml` only if source availability is already represented there; otherwise use a small explicit static lab profile and defer user configuration.

- [ ] Test full, partial, missing, and unknown source inventory cases.
- [ ] Weighted score = observed alert evidence × available required-source quality ratio; missing requirements reduce score to zero/partial as specified.
- [ ] Return missing source names and score basis so UI consumers can explain gaps.
- [ ] No default “all sources enabled” profile that inflates coverage.

### Task 3: Use one canonical function for API and Navigator

**Files:**
- Modify: `src/sentinel/api/app.py`
- Modify: `src/sentinel/auth.py`
- Test: `tests/test_api.py`
- Test: `tests/test_auth.py`
- Test: `tests/test_attack_coverage.py`
- Modify: `docs/DATA_CONTRACTS.md`

- [ ] Build endpoint payload and Navigator layer from the same `CoverageReport` result.
- [ ] Preserve ATT&CK Navigator v4.5 required fields; test layer version/domain/techniques/score/color and empty coverage.
- [ ] Analyst/engineer roles can read coverage; viewer role policy follows existing least-privilege convention and is explicitly tested.
- [ ] Keep `/v1/attack-coverage/navigator` export consistent with source availability and observed alerts, not detector invocation counts.
- [ ] Update contract/version docs and run focused API/auth tests.
