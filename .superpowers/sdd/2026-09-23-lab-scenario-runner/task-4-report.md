# Task 4 Report

Implemented the profile-gated `lab-scenario-runner` Compose service and focused safety coverage.

## Changes

- Added `lab-scenario-runner` under the `lab` profile.
- Invokes the checked-in `scripts/run_lab_scenario.py` runner with the checked-in manifest.
- Uses `idurar-target:8888` and `api:8100` service names.
- Mounts `configs/lab/scenarios.json` read-only.
- Supplies `SENTINEL_API_KEY` through the environment.
- Uses `restart: "no"`.
- Does not set `network_mode` or `privileged`.
- Added tests covering isolation, profile gating, runner arguments, manifest mount, API key wiring, and existing profile values.

## Verification

- `uv run pytest tests/test_compose_lab.py -q`: 2 passed.
- `docker compose config --profiles`: reported `demo`, `demo-admin`, `lab`, `obs`, and `realtime`.
- `docker compose config --quiet`: passed.
- `uv run ruff check src tests scripts`: passed.
- `uv run ruff format --check src tests scripts`: passed.
- `uv run pytest -q`: all collected tests passed.

## Concern

- The full test gate emits existing Starlette/httpx and anyio deprecation warnings; no failures occurred.
