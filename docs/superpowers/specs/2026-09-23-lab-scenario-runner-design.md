# Isolated Lab Scenario Runner

**Goal:** Provide a reproducible, Docker-isolated demonstration path that generates synthetic attack-progression telemetry against the Idurar lab target and feeds it through the existing SENTINEL event API.

## Scope

Phase 1 adds a bounded scenario runner, scenario manifests, Compose wiring, and end-to-end contract tests. Scenarios are restricted to the Compose lab network and use synthetic credentials/data. The runner does not implement credential theft, MITM, wireless attacks, covert transport, persistence, evasion, or arbitrary command execution.

The existing `UnifiedEvent` contract is reused. No new production model fields are added in this phase, so no schema version bump is required.

## Architecture

```text
scenario-runner -> idurar-target:8888
       |                 |
       +-- replay events-+
               |
               v
        sentinel-api:8100
```

The runner executes a named scenario from a checked-in manifest. Each step has a stage, a bounded request pattern, and synthetic event features. The API receives those events through `/v1/events`, allowing the existing windowing, detectors, correlation, and forecast code to remain the source of truth.

## Safety Boundaries

- The runner is enabled only by a dedicated Compose `lab` profile.
- The runner can resolve only the Compose target service, not host networking.
- Scenario IDs are an allowlist, not arbitrary shell commands.
- Requests use fixed local paths and synthetic values.
- The runner exits after one scenario; it is not a persistent attack service.
- Production Compose profiles do not include the runner.

## Acceptance Criteria

- A scenario manifest validates unknown fields as errors.
- A valid scenario produces ordered telemetry for at least reconnaissance and authentication-abuse stages.
- The runner refuses unknown scenario IDs and missing API keys.
- Compose can run the runner only under the lab profile.
- An end-to-end test proves generated events can be posted to the existing API contract.
- Existing SENTINEL tests and lint remain green.

## Deferred Work

- HTTP/auth log adapters beyond the existing event contract.
- Graph features and model retraining.
- Additional application-specific Idurar endpoint coverage.
- Production deployment changes beyond isolated lab Compose wiring.
