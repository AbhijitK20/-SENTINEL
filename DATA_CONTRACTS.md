# Data Contracts

## Raw Event Contract

Each event must have a timestamp or an explicit validation error. Source format and extraction version are retained as metadata.

## Flow Event

Required conceptual fields: timestamp, source/destination endpoint, ports, protocol, TCP flags where available, bytes, packets, duration, IAT statistics, and directionality. Missing fields are represented as unavailable, never silently invented.

## Packet Event

Required conceptual fields: timestamp, session identity where derivable, TTL, TCP window, fragmentation flags, payload-size summary, port-scan indicators, and retransmission count. Parser version and packet count are retained.

## Network State

```json
{
  "window_start": "timestamp",
  "window_end": "timestamp",
  "features": {"feature_name": 0.0},
  "entities": ["entity-id"],
  "edge_summary": [],
  "coverage": {"flow": true, "packet": true},
  "source_ids": ["event-id"]
}
```

## Forecast Output

```json
{
  "input_window": "timestamp-range",
  "horizon": 3,
  "model_version": "version",
  "probability_timeline": [],
  "predicted_stage": {"name": "Lateral Movement", "probability": 0.0},
  "affected_entities": [],
  "driving_features": [],
  "warnings": []
}
```

## Contract Rules

- Timestamps and horizon are mandatory for forecasts.
- Observed and predicted values must be distinguishable.
- Every explanation references available input evidence.
- Warnings expose missing telemetry and uncertainty.
