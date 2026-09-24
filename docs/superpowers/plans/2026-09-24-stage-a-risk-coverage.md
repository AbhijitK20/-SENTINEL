# Stage A: Evidence-Backed Risk and Coverage Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Keep this stage isolated from B–D.

**Goal:** Make SENTINEL risk and ATT&CK coverage outputs traceable to measured findings and available telemetry rather than technique-name lookup estimates.

**Architecture:** Preserve the existing `AttackFinding`, `RiskAssessment`, and API response shape wherever possible. Keep asset/probability/severity risk fusion as the supported baseline, remove unreferenced speculative enrichment, and make coverage distinguish detector capability, telemetry availability, and observed alert evidence.

**Tech Stack:** Python 3.12, Pydantic, FastAPI, pytest, Ruff; no new dependency.

**Spec:** `docs/superpowers/specs/2026-09-24-research-to-sentinel-design.md`

## Global Constraints

- Contracts use Pydantic with `extra="forbid"`; public contract changes update `docs/DATA_CONTRACTS.md` and version metadata.
- Never label per-technique constants as EPSS or KEV evidence.
- Preserve analyst-approved recommendations; no automated enforcement.
- Every modified module and its tests must be read before edits.
- Run `uv run ruff check src tests scripts && uv run ruff format --check src tests scripts && uv run pytest -q`.

---

### Task 1: Define truthful risk inputs and remove unsupported enrichment from incident risk

**Files:**
- Modify: `src/sentinel/assets.py`
- Modify: `src/sentinel/correlation.py`
- Modify: `src/sentinel/threat_enrichment.py`
- Test: `tests/test_correlation.py`
- Test: new `tests/test_threat_enrichment.py`

**Interfaces:**
- Keep `fuse_risk(probability, severity, affected_assets, registry)` callable by existing callers.
- Remove `enrichment_factor` unless a concrete CVE-linked provenance contract is implemented in this stage; findings currently have no CVE field.
- Retain only genuinely used transition/prediction helpers; remove the unused technique-indexed EPSS/KEV maps, stale geometric-risk helper or auto-block helper when no production consumer exists.

- [ ] **Step 1: Read all callers and current risk tests**

Run: `uv run pytest tests/test_correlation.py -q`

Inspect `grep` results for `fuse_risk`, `enriched_risk_factor`, `chain_risk_score`, `should_auto_block`, and `KEV_TECHNIQUES` before editing.

- [ ] **Step 2: Add failing risk provenance tests**

Add tests proving attack technique alone does not add threat-intelligence risk, registered critical assets still score above unknown assets, and risk stays in `[0,1]`.

- [ ] **Step 3: Restore one risk formula**

Use a single documented formula in `assets.py`; retain existing weighting unless test review exposes inconsistent bounds. Remove the call to `enriched_risk_factor()` from `fuse_incident_risk()`.

- [ ] **Step 4: Remove misleading unused helpers**

Delete technique-indexed EPSS/KEV estimates and unused auto-block / chain-risk helpers. Keep the transition predictor only if Stage B will replace it with a data-derived source; otherwise remove it in Stage B after migration.

- [ ] **Step 5: Run focused tests and lint**

Run: `uv run pytest tests/test_correlation.py tests/test_threat_enrichment.py -q`

Expected: all risk provenance, bounds, and registry tests pass.

### Task 2: Correct attack coverage semantics

**Files:**
- Modify: `src/sentinel/api/app.py`
- Modify: `src/sentinel/detectors.py`
- Test: `tests/test_api.py`
- Test: `tests/test_auth.py`
- Test: new `tests/test_attack_coverage.py`
- Modify: `docs/DATA_CONTRACTS.md`

**Interfaces:**
- `GET /v1/attack-coverage` remains authenticated.
- Coverage reports separate `detector_implemented`, `telemetry_available`, and `alert_observed`; an emitted zero-probability finding counts only as detector execution, never as observed alert coverage.
- Existing response keys remain during migration; any new response keys are documented as API contract changes.

- [ ] **Step 1: Add tests for zero-probability and telemetry-gap cases**

Build findings with probability `0`, `is_alert=False` and telemetry warnings. Assert observed coverage is false while detector execution is true. Assert a positive alert marks only its mapped technique as observed.

- [ ] **Step 2: Add role tests**

Verify authorized analyst/engineer access and viewer denial for coverage endpoints.

- [ ] **Step 3: Implement a shared coverage builder**

Derive all coverage fields from `MITRE`, actual detector definitions, live findings, and observed `NetworkState.coverage`. Reuse it for both coverage and Navigator endpoints rather than duplicating loops.

- [ ] **Step 4: Update API contract docs and relevant version**

Document each coverage dimension and the meaning of missing telemetry. Do not claim external ATT&CK matrix-wide coverage from the nine internal detector categories.

- [ ] **Step 5: Run targeted API/auth tests**

Run: `uv run pytest tests/test_attack_coverage.py tests/test_api.py tests/test_auth.py -q`

Expected: correct coverage semantics and role behavior.

### Task 3: Verify risk and coverage behavior end-to-end

**Files:** no additional source changes unless verification finds a defect.

- [ ] Run full project gate.
- [ ] Run authenticated attack-coverage API test from a fresh test app and verify empty history yields zero observed techniques.
- [ ] Confirm recommendations remain advisory and no network-blocking action is called.
- [ ] Record only actual command outputs; do not add unproduced metrics to docs.
