# Product Backlog

| ID | Type | Item | Priority | Sprint | Status |
|---|---|---|---:|---:|---|
| PB-001 | Spike | Confirm dataset availability and licenses | P0 | 0 | PARTIAL - licence and citation confirmed; the dataset is NOT present in the repo and the cross-day real-data benchmark has NOT been run. See docs/CLAIMS.md. |
| PB-002 | Task | Freeze event, state, and prediction contracts | P0 | 0 | Done |
| PB-003 | Feature | CSV and PCAP ingestion | P0 | 1 | Done |
| PB-004 | Feature | Required flow and packet features | P0 | 1 | Done |
| PB-005 | Feature | Window, state, and transition construction | P0 | 2 | Done |
| PB-006 | Feature | Logistic-regression baseline | P0 | 3 | Done |
| PB-007 | Feature | Temporal transition model | P0 | 4 | Done |
| PB-008 | Feature | K-step rollout and probability timeline | P0 | 5 | Done (timeline + recursive rollout implemented; lead on synthetic data limited by window granularity) |
| PB-009 | Feature | Stage mapping and explanations | P0 | 6 | Done (rule-based; synthetic data) |
| PB-010 | Feature | Offline interface and replay | P0 | 7 | Done (replay eval, report export, guided Demo tab with observed/forecast separation) |
| PB-011 | Task | Run leakage-safe benchmark | P0 | 7 | PARTIAL - synthetic benchmark done (`make bench-backtest`, `make bench-detectors`, `make bench-world`); the CIC-IDS2017 real-data benchmark is PENDING. |
| PB-012 | Task | Produce final SIH materials | P0 | 8 | PARTIAL - materials exist; the real-data section of RESULTS.md is PENDING and the abstract's real-data claim was withdrawn. |

## Prioritization

- P0: required for PS compliance or a credible demo
- P1: strong differentiator that follows the core path
- P2: useful enhancement if time remains
