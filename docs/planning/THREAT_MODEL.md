# Threat Model

## Assets

- Network telemetry
- Model weights and configurations
- Forecast reports
- Dataset labels and split metadata
- Analyst decisions based on output

## Threats

- Poisoned or manipulated telemetry
- Data leakage between train and test
- Model overconfidence
- Adversarial traffic evading features
- Sensitive identifier exposure
- False positives causing analyst fatigue
- False negatives causing missed progression
- Unsafe automation based on a probabilistic forecast

## Mitigations

- Validate and version inputs.
- Run leakage audits.
- Display uncertainty and coverage.
- Record evidence provenance.
- Keep response manual in the prototype.
- Test failure cases and document limitations.
