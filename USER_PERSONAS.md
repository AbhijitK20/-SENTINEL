# User Personas

## Persona 1: SOC Analyst

- Goal: prioritize active investigations and decide what to inspect next.
- Pain: many alerts lack temporal context and explainable future impact.
- Needs: current state, forecast horizon, likely stage, affected entities, evidence.
- Success: can understand and validate a forecast within one minute.

## Persona 2: Incident Responder

- Goal: reconstruct progression and contain likely next targets.
- Pain: evidence is distributed across event types and timestamps.
- Needs: timeline, entity graph, observed-versus-predicted distinction, exportable report.
- Success: can form a defensible investigation hypothesis without automatic blocking.

## Persona 3: CII Security Operator

- Goal: monitor operationally important assets with minimal external dependencies.
- Pain: sensitive telemetry cannot always leave the environment.
- Needs: offline processing, uncertainty, asset prioritization, audit trail.
- Success: can run the prototype locally and identify high-priority trajectories.

## Persona 4: SIH Evaluator

- Goal: determine whether the team solved the stated problem rather than built a static IDS.
- Pain: impressive interfaces may hide unsupported ML claims.
- Needs: clear architecture, baseline comparison, reproducible demo, explainability.
- Success: sees future-state rollout and measurable forecast value in two minutes.
