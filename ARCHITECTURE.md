# Architecture Plan

## System Context

```text
CSV flow records / PCAP / replay
              |
              v
      Ingestion and validation
              |
              v
    Unified timestamped events
              |
              v
       Time-window state builder
              |
       +------+------+
       |             |
       v             v
  State vector   Entity graph
       |             |
       +------+------+
              v
      Temporal transition model
              |
              v
        K-step forward rollout
              |
       +------+------+------+
       |             |       |
       v             v       v
 Probability     Stage     Evidence
 timeline        mapping   and assets
              |
              v
        Offline analyst interface
```

## Components

- Ingestion: reads CSV and PCAP locally and reports coverage.
- Feature extraction: derives required flow and packet attributes.
- State builder: aggregates events into ordered windows.
- Model: learns state-transition dynamics and forecast heads.
- Rollout: recursively predicts K future windows.
- Mapping: converts predicted behaviour to documented attack-stage vocabulary.
- Explainability: ranks features and supporting events without claiming causality.
- Interface: separates observed state, forecast, evidence, and evaluation.

## Operating Modes

- Training: local dataset preparation, split, training, evaluation, artifact export.
- Batch inference: analyze an uploaded CSV or PCAP.
- Replay: advance through a deterministic scenario for demonstration.

## Design Principles

- Local-first; no cloud API is required at runtime.
- Stable contracts between pipeline stages.
- Model output must retain provenance: input window, model version, horizon.
- Components should fail clearly when required features are unavailable.
- The prototype recommends investigation; it does not automatically block traffic.
