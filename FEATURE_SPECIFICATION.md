# Feature Specification

## Flow Features

| Feature family | Examples | Leakage risk |
|---|---|---|
| Endpoint | source/destination, ports, protocol | Entity memorization |
| Flags | SYN, ACK, FIN, RST, PSH, URG counts/ratios | Low if windowed correctly |
| Volume | bytes, packets, flow count | Low if current-window only |
| Timing | duration, IAT mean/variance/max | Future aggregation risk |
| Directionality | bidirectional ratios | Low if event complete |

## Packet Features

| Feature family | Examples | Leakage risk |
|---|---|---|
| TTL | mean, variance, range | Low |
| TCP | window size statistics | Low |
| IP | fragment flags | Low |
| Payload | size distribution, summary statistics | Avoid payload labels |
| Scanning | sequential/random access indicators | Derivation must be documented |
| Reliability | retransmissions | Low if current-window only |

## Feature Rules

- Every feature has source, unit, aggregation, missing-value behaviour, and version.
- Raw identifiers may be anonymized for privacy and controlled generalization tests.
- Labels, future stage names, and scenario identifiers are never model inputs.
- Normalization parameters are fitted on training data only.
