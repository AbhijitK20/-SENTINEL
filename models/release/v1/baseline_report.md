# Baseline Report

## Experiment Identity

- Feature version: state-features-v2
- Split strategy: scenario-held-out (whole scenarios per split)
- Seed: 42
- Model version: logistic-regression-baseline-v1
- Target: infiltration at horizon +5 windows (current window only)
- Model SHA-256: `3cd4494e524fb2f1d57b5eab9665daa8069545a5a6a064966c2d164cace67899`
- Configuration: `{"excluded_features":[],"regularization_c":1.0,"class_weight":"balanced","max_iterations":1000,"decision_threshold":0.5}`
- Runtime: python=3.12.14, scikit_learn=1.9.0, numpy=2.5.3, platform=Linux-7.0.0-34-generic-x86_64-with-glibc2.43

## Split Audit

| Split | Scenarios | Samples | Positives |
|---|---:|---:|---:|
| train | 6 | 321 | 93 |
| validation | 2 | 103 | 31 |
| test | 2 | 104 | 42 |

- Scenario isolation: pass
- Window isolation: pass

## Baseline Metrics

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.6452 | 0.5758 | 0.6346 |
| Recall | 0.8602 | 0.6129 | 0.7857 |
| F1 | 0.7373 | 0.5938 | 0.7021 |
| False-positive rate | 0.1930 | 0.1944 | 0.3065 |
| PR-AUC | 0.8383 | 0.6622 | 0.6620 |

- Training time: 253.3 ms
- Inference latency: 2.0 us/sample

## Feature Weights (standardized inputs)

| Feature | Coefficient |
|---|---:|
| dst_port_entropy | +1.7474 |
| packets_mean | -1.4819 |
| flag_syn_ack_ratio | +1.2118 |
| flag_ack_ratio | +0.7769 |
| ack_count_mean | +0.7769 |
| flag_no_ack_share | -0.7769 |
| retransmission_count | -0.7405 |
| retransmission_sum | -0.7405 |
| tcp_window_size_std | +0.6046 |
| retransmission_mean | +0.5838 |
| retransmission_rate | +0.5838 |
| tcp_window_size_mean | -0.4989 |
| tcp_window_size_min | +0.4756 |
| iat_cv | +0.4735 |
| iat_mean | -0.4143 |
| iat_mean_mean | -0.4143 |
| ttl_nunique | -0.4135 |
| frag_df_share | +0.4130 |
| bytes_p90 | -0.4094 |
| payload_size_p50 | +0.4006 |
| iat_variance_max | +0.3974 |
| payload_size_mean | -0.3876 |
| iat_variance_mean | -0.3753 |
| dst_port_sequential_score | -0.3737 |
| bytes_mean | +0.3695 |
| flag_psh_ratio | +0.3595 |
| payload_size_std | +0.3357 |
| ack_count_sum | +0.3348 |
| duration_max | -0.3283 |
| packets_max | +0.3271 |
| iat_mean_max | -0.3223 |
| iat_max | -0.3223 |
| iat_mean_var | -0.3193 |
| iat_var | -0.3193 |
| ttl_mean | +0.3091 |
| ttl_std | -0.2971 |
| tcp_flags_nunique | -0.2930 |
| tcp_window_size_max | -0.2894 |
| ttl_var | -0.2650 |
| payload_size_p90 | +0.2455 |
| failed_auth | +0.2328 |
| failed_auth_sum | +0.2328 |
| ports_per_host_max | +0.2130 |
| iat_min | +0.2062 |
| iat_mean_min | +0.2062 |
| frag_offset_nunique | -0.2048 |
| duration_mean | +0.1989 |
| duration | +0.1989 |
| bytes_max | +0.1876 |
| dst_port_randomness | +0.1797 |
| payload_size_entropy | -0.1713 |
| dst_port_wellknown_share | +0.1676 |
| dst_port_low_share | -0.1676 |
| syn_count_sum | +0.1655 |
| syn_count | +0.1655 |
| flow_event_count | +0.1655 |
| event_count | +0.1655 |
| packet_event_count | +0.1655 |
| ttl_nunique_per_src | -0.1649 |
| dst_port_nunique | +0.1623 |
| destination_port_nunique | +0.1623 |
| source_port_nunique | +0.1620 |
| ttl_min | +0.1611 |
| src_port_ephemeral_share | -0.1389 |
| flag_rst_ratio | -0.1174 |
| rst_count_mean | -0.1174 |
| bidirectional_ratio_std | -0.0773 |
| payload_size | +0.0750 |
| payload_size_sum | +0.0750 |
| flag_fin_ratio | +0.0411 |
| fin_count_mean | +0.0411 |
| packets | +0.0403 |
| packets_sum | +0.0403 |
| ack_count | +0.0379 |
| iat_p90 | +0.0324 |
| iat_mean_p90 | +0.0324 |
| fin_count_sum | +0.0211 |
| bidirectional_ratio_mean | -0.0204 |
| bytes_std | -0.0195 |
| rst_count_sum | +0.0185 |
| rst_count | +0.0185 |
| duration_std | +0.0134 |
| bytes | +0.0073 |
| bytes_sum | +0.0073 |
| proto_tcp_share | +0.0000 |
| proto_icmp_share | +0.0000 |
| ttl_max | +0.0000 |
| syn_count_mean | +0.0000 |
| urg_count_sum | +0.0000 |
| urg_count_mean | +0.0000 |
| protocol_nunique | +0.0000 |
| proto_udp_share | +0.0000 |
| flag_urg_ratio | +0.0000 |
| flag_xmas_share | +0.0000 |
| high_port_ratio | +0.0000 |
| flag_syn_ratio | +0.0000 |
| frag_mf_share | +0.0000 |
| external_destination_count | +0.0000 |

## Interpretation

- `n/a` marks a metric that is undefined for the split (for example, no positives or no predicted positives); it is not zero.
- The baseline sees one window and cannot express ordering; it is a reference, not a forecast.
- Results describe the evaluated dataset and split only. Dataset identity and licensing must be recorded alongside this report before any external claim.
