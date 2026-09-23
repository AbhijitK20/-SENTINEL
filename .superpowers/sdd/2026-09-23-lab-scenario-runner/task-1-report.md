# Task 1 Implementation Report

## Status

Implemented Task 1: strict Pydantic scenario contracts and JSON manifest loader.

## Files Changed

- `src/sentinel/lab_scenarios.py`
  - Added `LabStep`, `LabScenario`, and top-level `LabManifest` Pydantic models.
  - Applied `ConfigDict(extra="forbid")` to every contract.
  - Added `load_scenario(path: Path, scenario_id: str) -> LabScenario`.
  - Unknown scenario IDs raise `ValueError`.
- `tests/test_lab_scenarios.py`
  - Added valid scenario loading coverage.
  - Added unknown-field rejection coverage.
  - Added unknown scenario rejection coverage.

## Commit

Implementation commit:

`ea6355ac968f0ab54c5cbec6062420085bdb9d54`

## Verification

Initial focused-test command, before implementation:

```text
$ uv run pytest tests/test_lab_scenarios.py -q
ERROR: file or directory not found: tests/test_lab_scenarios.py
```

Focused tests after implementation:

```text
$ uv run pytest tests/test_lab_scenarios.py -q
...                                                                      [100%]
```

Ruff lint:

```text
$ uv run ruff check src/sentinel/lab_scenarios.py tests/test_lab_scenarios.py
All checks passed!
```

Ruff format check:

```text
$ uv run ruff format --check src/sentinel/lab_scenarios.py tests/test_lab_scenarios.py
2 files already formatted
```

## Concerns

- The loader currently supports the Task 1 JSON manifest shape with a top-level `scenarios` mapping. The checked-in manifest fixture is intentionally deferred to Task 2.
- Full-project tests and the repository-wide gate were not run because the requested Task 1 verification scope was focused tests and Ruff.
