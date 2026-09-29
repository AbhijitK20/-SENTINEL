# Baseline Report

## Experiment Identity

- Feature version: state-features-v1
- Split strategy: scenario-held-out (whole scenarios per split)
- Seed: 42
- Model version: logistic-regression-baseline-v1
- Target: infiltration at horizon +5 windows (current window only)
- Model SHA-256: `fb4e6014f0b36112a58fc861c5c1f7a07d5bc0264706a1eb1bd1c965d4a7967b`
- Configuration: `{"excluded_features":["source_port","destination_port","protocol","tcp_flags"],"regularization_c":1.0,"class_weight":"balanced","max_iterations":1000,"decision_threshold":0.5}`
- Runtime: python=3.12.13, scikit_learn=1.9.0, numpy=2.5.3, platform=Linux-7.0.0-34-generic-x86_64-with-glibc2.43

## Split Audit

| Split | Scenarios | Samples | Positives |
|---|---:|---:|---:|
| train | 19 | 2910 | 599 |
| validation | 6 | 787 | 290 |
| test | 7 | 818 | 41 |

- Scenario isolation: pass
- Window isolation: pass

## Baseline Metrics

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.5006 | 0.4880 | 0.1506 |
| Recall | 0.7546 | 0.2103 | 0.6098 |
| F1 | 0.6019 | 0.2940 | 0.2415 |
| False-positive rate | 0.1952 | 0.1288 | 0.1815 |
| PR-AUC | 0.6603 | 0.4515 | 0.2715 |

- Training time: 26.6 ms
- Inference latency: 0.3 us/sample

## Feature Weights (standardized inputs)

| Feature | Coefficient |
|---|---:|
| dst_port_entropy | +5.2707 |
| dst_port_wellknown_share | +3.2992 |
| source_port_nunique | +1.9870 |
| destination_port_nunique | -1.9288 |
| dst_port_nunique | -1.9288 |
| psh_count | -1.5163 |
| ports_per_host_max | +1.1128 |
| ack_count_sum | +1.0680 |
| ack_count | +1.0680 |
| packets_max | -1.0589 |
| flow_iat_mean_ms | +0.8600 |
| high_port_ratio | +0.8020 |
| rst_count_mean | -0.7205 |
| dst_port_low_share | +0.6659 |
| bytes_p90 | -0.6559 |
| bytes_std | +0.6034 |
| fin_count_sum | -0.5330 |
| fin_count | -0.5330 |
| bytes_mean | -0.5036 |
| duration_max | +0.4978 |
| syn_count | +0.4354 |
| syn_count_sum | +0.4354 |
| duration_std | -0.3578 |
| packets_sum | +0.3284 |
| packets | +0.3284 |
| rst_count | +0.2534 |
| rst_count_sum | +0.2534 |
| fin_count_mean | -0.2523 |
| duration_mean | +0.1930 |
| duration | +0.1930 |
| syn_count_mean | -0.1539 |
| packets_mean | +0.1371 |
| src_port_ephemeral_share | -0.1088 |
| bytes | +0.1086 |
| bytes_sum | +0.1086 |
| ack_count_mean | -0.0644 |
| dst_port_sequential_score | -0.0454 |
| dst_port_randomness | +0.0454 |
| event_count | +0.0188 |
| flow_event_count | +0.0188 |
| bytes_max | +0.0055 |
| ttl_nunique_per_src | +0.0000 |
| flag_urg_ratio | +0.0000 |
| iat_p90 | +0.0000 |
| iat_var | +0.0000 |
| packet_event_count | +0.0000 |
| iat_min | +0.0000 |
| retransmission_count | +0.0000 |
| proto_icmp_share | +0.0000 |
| proto_udp_share | +0.0000 |
| proto_tcp_share | +0.0000 |
| retransmission_rate | +0.0000 |
| flag_xmas_share | +0.0000 |
| frag_mf_share | +0.0000 |
| frag_df_share | +0.0000 |
| frag_offset_nunique | +0.0000 |
| iat_mean | +0.0000 |
| iat_max | +0.0000 |
| iat_cv | +0.0000 |
| external_destination_count | +0.0000 |
| flag_syn_ratio | +0.0000 |
| flag_rst_ratio | +0.0000 |
| flag_syn_ack_ratio | +0.0000 |
| flag_psh_ratio | +0.0000 |
| flag_no_ack_share | +0.0000 |
| flag_fin_ratio | +0.0000 |
| flag_ack_ratio | +0.0000 |

## Interpretation

- `n/a` marks a metric that is undefined for the split (for example, no positives or no predicted positives); it is not zero.
- The baseline sees one window and cannot express ordering; it is a reference, not a forecast.
- Results describe the evaluated dataset and split only. Dataset identity and licensing must be recorded alongside this report before any external claim.
