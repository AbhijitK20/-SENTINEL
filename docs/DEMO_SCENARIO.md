# Demo Scenario

## Scenario

Reconnaissance to lateral-movement trajectory in a small enterprise-like network.

## Actors And Assets

- Workstation-17: suspicious source
- Auth-Service: authentication target
- Server-03: likely lateral-movement target
- Other internal hosts: benign context

## Timeline

1. Baseline traffic establishes normal behaviour.
2. Workstation-17 contacts many new destinations.
3. Port and timing patterns become abnormal.
4. Failed authentication activity rises.
5. New internal connections appear.
6. Model forecasts lateral movement.
7. Replay reveals the target-stage event for comparison.

## Success Criteria

- Forecast appears before the target stage is observable.
- Evidence names relevant traffic patterns and entities.
- Actual and predicted stages are visually distinct.
- Replay is repeatable from the same configuration.
