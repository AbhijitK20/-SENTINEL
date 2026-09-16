# Baseline Report

## Experiment Identity

- Feature version: state-features-v1
- Split strategy: scenario-held-out (whole scenarios per split)
- Seed: 42
- Model version: logistic-regression-baseline-v1
- Target: infiltration at horizon +5 windows (current window only)
- Model SHA-256: `7b1fafedbc094b4c37747959bf01a2c80032ab01973c35a13734acb4ca8c5c43`
- Configuration: `{"excluded_features":["source_port","destination_port","protocol","tcp_flags"],"regularization_c":1.0,"class_weight":"balanced","max_iterations":1000,"decision_threshold":0.5}`
- Runtime: python=3.11.15, scikit_learn=1.9.0, numpy=2.4.6, platform=Windows-10-10.0.26200-SP0

## Split Audit

| Split | Scenarios | Samples | Positives |
|---|---:|---:|---:|
| train | 6 | 360 | 108 |
| validation | 2 | 120 | 36 |
| test | 2 | 120 | 36 |

- Scenario isolation: pass
- Window isolation: pass

## Baseline Metrics

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.7823 | 0.7209 | 0.7838 |
| Recall | 0.8981 | 0.8611 | 0.8056 |
| F1 | 0.8362 | 0.7848 | 0.7945 |
| False-positive rate | 0.1071 | 0.1429 | 0.0952 |
| PR-AUC | 0.9502 | 0.9253 | 0.9319 |

- Training time: 14.8 ms
- Inference latency: 1.6 us/sample

## Feature Weights (standardized inputs)

| Feature | Coefficient |
|---|---:|
| bytes | +2.6096 |
| rst_count | +1.1263 |
| ack_count | +1.0078 |
| packets | +0.9985 |
| failed_auth | +0.7817 |
| bidirectional_ratio | -0.1468 |
| duration | -0.1153 |
| event_count | -0.0877 |
| flow_event_count | -0.0877 |
| syn_count | -0.0877 |
| iat_mean | +0.0693 |
| packet_event_count | +0.0000 |
| external_destination_count | +0.0000 |

## Interpretation

- `n/a` marks a metric that is undefined for the split (for example, no positives or no predicted positives); it is not zero.
- The baseline sees one window and cannot express ordering; it is a reference, not a forecast.
- Results describe the evaluated dataset and split only. Dataset identity and licensing must be recorded alongside this report before any external claim.
