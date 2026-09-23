# Task 6 Implementation Report

## Status

Implemented the safe operator documentation for the isolated synthetic `lab`
profile.

## Files Changed

- `docs/DEMO_SCENARIO.md`
  - Documents the bounded `recon-auth-progression` scenario, service names,
    ports, verified dry-run command, live-run prerequisite, cleanup, and
    synthetic/demo limitations.
- `docs/DEPLOYMENT.md`
  - Replaced unrelated deployment paths with the profile-gated lab operator
    path and explicitly records that the checked-in Compose file has no
    `idurar-target` service.

## Honesty Check

- Commands were limited to the checked-in Compose `lab` profile and the
  verified dry-run/start/cleanup behavior.
- No real-traffic, production, hosted, observability, threat-feed, or measured
  performance claims were retained in these task-scoped docs.
- Synthetic/demo caveats are explicit.

## Verification

Focused tests:

```text
uv run pytest tests/test_compose_lab.py tests/test_run_lab_scenario.py tests/test_lab_scenarios.py -q
20 passed
```

Compose checks:

```text
docker compose config --profiles
docker compose --profile lab config --services
```

The profile and services resolved successfully. The first documented dry-run
form exposed a Compose argument-forwarding mistake: `docker compose run` treats
arguments after the service name as a replacement command. The docs now invoke
the image command explicitly with `uv run --no-sync python ...`.

The corrected documented dry run completed successfully and printed all four
steps with `scenario=recon-auth-progression steps=4 dry_run=True`.

Full gate:

```text
uv run ruff check src tests scripts && uv run ruff format --check src tests scripts && uv run pytest -q
All checks passed!
177 files already formatted
all tests passed
```

## Commit

`b2815c8` (`docs: document isolated lab scenario`)

## Concerns

- The checked-in Compose file does not define `idurar-target`, so a live
  scenario run cannot be claimed without adding or attaching that isolated
  target service.
- Existing unrelated worktree changes were left untouched.
