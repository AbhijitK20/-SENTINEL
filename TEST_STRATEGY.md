# Test Strategy

## Unit Tests

- Input validation and schema handling
- Flow and packet feature calculations
- Window aggregation
- Label and transition construction
- Stage mapping
- Probability and report serialization

## Integration Tests

- CSV through forecast output
- PCAP through forecast output
- Training artifact through offline inference
- Replay through forecast-versus-reality comparison

## ML Tests

- No future columns in current-state features
- Split isolation by scenario
- Fixed seed reproducibility
- Output shape and probability validity
- Rollout horizon correctness
- Attribution output availability

## Operational Tests

- Clean local setup
- No network dependency at runtime
- Malformed input produces actionable errors
- Demo replay is deterministic
- Large input fails gracefully or reports resource limits
