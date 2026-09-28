# Isolated Lab Scenario Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Docker-isolated, replayable synthetic attack-progression runner for the Idurar lab target and SENTINEL API.

**Architecture:** A small Python CLI reads an allowlisted JSON scenario manifest, sends bounded requests to the lab target, and posts normalized `UnifiedEvent` batches to the existing SENTINEL `/v1/events` endpoint. Docker Compose exposes it only under a `lab` profile; the normal deployment remains unchanged.

**Tech Stack:** Python standard library, existing Pydantic contracts, Docker Compose, pytest.

**Spec:** `docs/superpowers/specs/2026-09-23-lab-scenario-runner-design.md`

## Global Constraints

- The runner is restricted to the Compose lab network and synthetic data.
- No credential theft, MITM, wireless attacks, covert transport, persistence, evasion, or arbitrary command execution.
- Contracts use Pydantic `extra="forbid"`.
- Core library remains offline-first; network access stays in `scripts/`.
- Existing version strings are unchanged because no existing contract changes.
- Run `uv run ruff check src tests scripts && uv run ruff format --check src tests scripts && uv run pytest -q` before completion.

### Task 1: Scenario contracts and manifest loader

**Files:**
- Create: `src/sentinel/lab_scenarios.py`
- Create: `tests/test_lab_scenarios.py`

**Interfaces:**
- `load_scenario(path: Path, scenario_id: str) -> LabScenario`
- `LabScenario.steps: list[LabStep]`
- `LabStep.stage`, `LabStep.method`, `LabStep.path`, `LabStep.features`

- [ ] Write tests for valid loading, unknown-field rejection, and unknown scenario rejection.
- [ ] Run `uv run pytest tests/test_lab_scenarios.py -q` and verify failure.
- [ ] Implement minimal Pydantic models with `extra="forbid"` and a loader that selects one scenario by ID.
- [ ] Run the focused tests and verify pass.
- [ ] Run `uv run ruff check src/sentinel/lab_scenarios.py tests/test_lab_scenarios.py`.

### Task 2: Scenario manifest fixtures

**Files:**
- Create: `configs/lab/scenarios.json`
- Modify: `tests/test_lab_scenarios.py`

**Interfaces:**
- Manifest contains `recon-auth-progression`.
- Steps use fixed local paths and synthetic request values.

- [ ] Add a manifest with reconnaissance, failed-login, API-probe, and synthetic-upload steps.
- [ ] Add a test that loads the checked-in manifest and asserts monotonically ordered stages.
- [ ] Run `uv run pytest tests/test_lab_scenarios.py -q`.

### Task 3: Lab runner CLI

**Files:**
- Create: `scripts/run_lab_scenario.py`
- Create: `tests/test_run_lab_scenario.py`

**Interfaces:**
- `main(argv: list[str] | None = None) -> int`
- CLI flags: `--scenario`, `--manifest`, `--target`, `--api`, `--api-key`, `--dry-run`.

- [ ] Test dry-run output and missing-key failure without network access.
- [ ] Implement allowlisted scenario loading, bounded HTTP requests, event creation using `UnifiedEvent`, and batched POSTs to `/v1/events`.
- [ ] Refuse targets whose hostname is not the configured Compose service name or loopback lab target.
- [ ] Run focused tests.
- [ ] Run `uv run ruff check scripts/run_lab_scenario.py tests/test_run_lab_scenario.py`.

### Task 4: Compose lab profile

**Files:**
- Modify: `docker-compose.yml`
- Create: `tests/test_compose_lab.py`

**Interfaces:**
- Service: `lab-scenario-runner`.
- Profile: `lab`.
- Target: existing Idurar service or documented external lab target name.

- [ ] Add a Compose configuration test that checks the service is profile-gated and has no host network mode or privileged flag.
- [ ] Add the minimal service with read-only manifest mount, API key environment, and one-shot restart policy.
- [ ] Keep `demo`, `obs`, and default profiles unchanged.
- [ ] Run the Compose-focused test and inspect `docker compose config --profiles`.

### Task 5: End-to-end API contract check

**Files:**
- Modify: `tests/test_api.py`
- Modify: `scripts/run_lab_scenario.py` only if the contract test exposes a mismatch

- [ ] Add a test posting generated scenario events to `/v1/events` with an authenticated test client.
- [ ] Assert the response contains alert status and forecast/incident-compatible fields already used by the API.
- [ ] Run the focused API tests.
- [ ] Run the full project gate.

### Task 6: Safe operator documentation

**Files:**
- Modify: `docs/DEMO_SCENARIO.md`
- Modify: `docs/DEPLOYMENT.md`

- [ ] Document only commands that run against the isolated lab profile and synthetic data.
- [ ] Document the expected ports and cleanup command.
- [ ] Mark claims as synthetic/demo where applicable.
- [ ] Run the documentation honesty check and full gate.
