# Product Backlog

| ID | Type | Item | Priority | Sprint | Status |
|---|---|---|---:|---:|---|
| PB-001 | Spike | Confirm dataset availability and licenses | P0 | 0 | Done (CIC-IDS2017 licensed for research with citation; downloaded, licence reviewed, cross-day real-data benchmark executed) |
| PB-002 | Task | Freeze event, state, and prediction contracts | P0 | 0 | Done |
| PB-003 | Feature | CSV and PCAP ingestion | P0 | 1 | Done |
| PB-004 | Feature | Required flow and packet features | P0 | 1 | Done |
| PB-005 | Feature | Window, state, and transition construction | P0 | 2 | Done |
| PB-006 | Feature | Logistic-regression baseline | P0 | 3 | Done |
| PB-007 | Feature | Temporal transition model | P0 | 4 | Done |
| PB-008 | Feature | K-step rollout and probability timeline | P0 | 5 | Done (timeline + recursive rollout implemented; lead on synthetic data limited by window granularity) |
| PB-009 | Feature | Stage mapping and explanations | P0 | 6 | Done (rule-based; synthetic data) |
| PB-010 | Feature | Offline interface and replay | P0 | 7 | Done (replay eval, report export, guided Demo tab with observed/forecast separation) |
| PB-011 | Task | Run leakage-safe benchmark | P0 | 7 | Done (synthetic benchmark + CIC-IDS2017 real-data benchmark with cross-day temporal splits; see REAL_BENCHMARK.md) |
| PB-012 | Task | Produce final SIH materials | P0 | 8 | Done (RESULTS.md, BENCHMARK.md, QUALITY_GATES.md, run_all.sh, Demo tab; real-data report added) |

## Prioritization

- P0: required for PS compliance or a credible demo
- P1: strong differentiator that follows the core path
- P2: useful enhancement if time remains
