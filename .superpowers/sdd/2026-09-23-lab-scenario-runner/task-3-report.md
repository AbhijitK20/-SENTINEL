# Task 3 Report

## Status

Implemented the bounded lab scenario runner and focused tests.

## Implementation

- Added `scripts/run_lab_scenario.py` with the required CLI flags.
- Loads only the selected validated manifest scenario.
- Allows only loopback targets or the `idurar-target` Compose service.
- Enforces the fixed manifest method/path allowlist.
- Builds `UnifiedEvent` payloads and posts batches to `/v1/events`.
- Requires an API key before execution and performs no network calls in dry-run mode.

## Verification

- Focused tests: 9 passed.
- Full gate: ruff check passed, format check passed, 323 tests passed.

## Concerns

- The runner intentionally supports only the checked-in synthetic endpoint allowlist; new lab endpoints require an explicit manifest/code change.
- Full pytest emitted existing dependency deprecation warnings from FastAPI/Starlette test utilities.

## Review Fixes

- Validated `--api` with the lab-only allowlist before any event POST.
- Added a maximum of 16 scenario steps and rejected non-allowlisted scenario IDs.
- Restricted normal execution to the checked-in manifest; custom manifests remain dry-run-only.
- Converted target/API URL failures, timeouts, and HTTP/network errors into controlled CLI exits.

## Review Fix Verification

- Focused tests: 14 passed.
- Full gate: ruff check passed, format check passed, 324 tests passed.
- Existing FastAPI/Starlette deprecation warnings remain non-fatal.
