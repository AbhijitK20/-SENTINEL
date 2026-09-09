# SIH26153 Requirements

## Source

Official source: https://sih.gov.in/sih2026PS

Problem statement: **AI based Network Attack Forecasting from Network Traffic Data**.

## Requirement Traceability

| ID | Requirement | Priority | Planned evidence |
|---|---|---:|---|
| REQ-PS-001 | Learn evolving network behaviour from traffic telemetry | P0 | State builder, temporal training results |
| REQ-PS-002 | Represent network state as feature vectors or graphs | P0 | State schema and architecture |
| REQ-PS-003 | Learn state-transition dynamics | P0 | Temporal model and rollout test |
| REQ-PS-004 | Support flow-level features | P0 | Flow schema and ingestion tests |
| REQ-PS-005 | Support packet-level features | P0 | PCAP parser and packet feature tests |
| REQ-PS-006 | Forecast future states for K windows | P0 | Rollout output and test |
| REQ-PS-007 | Estimate infiltration probability over time | P0 | Probability timeline |
| REQ-PS-008 | Map behaviour to recognised attack stages | P0 | MITRE mapping output |
| REQ-PS-009 | Explain each prediction | P0 | Evidence and attribution output |
| REQ-PS-010 | Generalise beyond memorized attack signatures | P0 | Scenario-held-out evaluation |
| REQ-PS-011 | Work fully offline | P0 | Offline acceptance test |
| REQ-PS-012 | Compare with logistic regression | P0 | Benchmark report |
| REQ-PS-013 | Provide reproducible training assets | P0 | Config, scripts, weights, README |
| REQ-PS-014 | Provide working demo interface | P0 | Offline demo recording |
| REQ-PS-015 | Provide SIH submission documents | P0 | Submission checklist |

## Derived Requirements

- REQ-DER-001: Dataset splits must prevent temporal and scenario leakage.
- REQ-DER-002: Forecasts must expose uncertainty and insufficient-evidence states.
- REQ-DER-003: Flow and packet features must be distinguishable in the feature schema.
- REQ-DER-004: A forecast must identify its input window and horizon.
- REQ-DER-005: The UI must distinguish observed behaviour from predicted behaviour.
- REQ-DER-006: Claims about improvement must use identical evaluation data and documented metrics.

## Traceability Rule

Every P0 requirement must link to at least one user story, one implementation feature, and one verification case before release candidate approval. A feature cannot be called complete because it exists visually; its acceptance evidence must be recorded.
