# Feature Catalog

| ID | Feature | Priority | Depends on |
|---|---|---:|---|
| F-001 | Offline CSV ingestion | P0 | Data contracts |
| F-002 | Offline PCAP ingestion | P0 | Data contracts |
| F-003 | Flow feature extraction | P0 | F-001 |
| F-004 | Packet feature extraction | P0 | F-002 |
| F-005 | Feature validation and coverage report | P0 | F-003, F-004 |
| F-006 | Time-window builder | P0 | F-005 |
| F-007 | Network-state encoder | P0 | F-006 |
| F-008 | Transition and label builder | P0 | F-007 |
| F-009 | Logistic-regression baseline | P0 | F-008 |
| F-010 | Temporal world model | P0 | F-008 |
| F-011 | K-step forward rollout | P0 | F-010 |
| F-012 | Infiltration probability timeline | P0 | F-011 |
| F-013 | Attack-stage prediction | P0 | F-010 |
| F-014 | MITRE-oriented mapping | P0 | F-013 |
| F-015 | Evidence and feature attribution | P0 | F-010 |
| F-016 | Affected-asset view | P1 | F-007, F-011 |
| F-017 | Network graph view | P1 | F-007 |
| F-018 | Forecast-versus-reality comparison | P0 | F-011 |
| F-019 | Benchmark report | P0 | F-009, F-010 |
| F-020 | Offline analyst interface and replay | P0 | F-012, F-015 |
| F-021 | Exportable prediction report | P1 | F-020 |

## Feature Acceptance Principle

Every feature needs a user story, requirement link, acceptance criteria, and verification evidence before being marked done.
