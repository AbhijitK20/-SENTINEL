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
    (flow aggregates AND packet headers)
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
   +-----------+-----------+
   |                       |
   v                       v
World model (RSSM)   Temporal GRU
latent dynamics      per-horizon
prior/posterior      nowcast
   |                       |
   v                       v
Open-loop imagination   K-step timeline
   |                       |
   +-----------+-----------+
               v
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

- Ingestion: reads CSV and PCAP locally and reports coverage. Packet headers are
  read from the serialized IP header, not from scapy's flag enum, so the
  fragmentation features see the bitmask a sensor would.
- Feature extraction: derives required flow and packet attributes. A window
  carries both levels: flow aggregations plus TTL spread, TCP window size, IP
  fragmentation, retransmissions, payload distribution, and inter-arrival
  statistics.
- State builder: aggregates events into ordered windows.
- World model (`world_model/`): RSSM with a deterministic core and a stochastic
  latent. `p(z_t | h_t)` never sees the observation; `q(z_t | h_t, e_t)` does;
  the decoder reconstructs the observation so the latent has to carry dynamics,
  not just the label. Three interchangeable cores: LSTM, GRU, causal
  transformer.
- World-model training (`world_model/train.py`): ELBO with free-nats KL
  weighting, KL warm-up, an **open-loop multi-step objective**, per-timestep risk
  and stage heads, validation-split early stopping, checksummed artifacts.
- Imagination (`world_model/imagine.py`): burn in through the posterior on
  observed history, then sample K futures from the prior with no observations.
  Reports between-sample spread as uncertainty and gradient saliency as
  attribution.
- File inference (\ile_forecast.py\): a PCAP or flow CSV is routed by suffix
  into windowed states and then into either forecaster. The dashboard, the CLI
  and the API all call this one function, and the result states which telemetry
  level the input actually carried.
- Temporal model: GRU per-horizon nowcast, the cheaper comparison point.
- Rollout: linear K-step next-state surrogate, retained as the linear baseline
  for transition quality. Its inputs are standardized and its map is projected to
  a non-expansive spectral norm, because a one-step optimum is expansive and
  rolling it out diverges.
- Mapping: converts predicted behaviour to documented attack-stage vocabulary.
- Explainability: ranks features and supporting events without claiming causality.
- Interface: separates observed state, forecast, evidence, and evaluation.

## How a World Model Is Judged Here

Detection F1 cannot distinguish a world model from a classifier, so the
architecture carries its own acceptance measurement:

    skill = 1 − mean|imagined − realized| / mean|persistence − realized|

over standardized state features, on held-out scenarios, with the model rolling
its own decoded state forward after the burn-in. The same measurement is applied
to the linear transition model, to persistence, and to an ablation with the
open-loop objective removed. Current measured values are in
[RESULTS.md](RESULTS.md#world-model---open-loop-state-prediction-the-core-deliverable).

## Operating Modes

- Training: local dataset preparation, split, training, evaluation, artifact export.
- Batch inference: analyze an uploaded CSV or PCAP.
- Replay: advance through a deterministic scenario for demonstration.

## Design Principles

- Local-first; no cloud API is required at runtime.
- Stable contracts between pipeline stages.
- Model output must retain provenance: input window, model version, horizon.
- A world model is judged on states it imagined, not on the windows it was shown.
- Recursive forecasts must expose their drift; open-loop error is reported per step.
- Components should fail clearly when required features are unavailable.
- The prototype recommends investigation; it does not automatically block traffic.
