# Baseline Report

## Experiment Identity

- Feature version: state-features-v1
- Split strategy: scenario-held-out (whole scenarios per split)
- Seed: 42
- Model version: logistic-regression-baseline-v1
- Target: infiltration at horizon +5 windows (current window only)
- Model SHA-256: `2eecf6be8be5b4e99f625c197d88e1a22b9bf99ac91fd2293be16040a8a08b50`
- Configuration: `{"excluded_features":[],"regularization_c":1.0,"class_weight":"balanced","max_iterations":1000,"decision_threshold":0.5}`
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
| Precision | 0.9558 | 0.8718 | 0.8684 |
| Recall | 1.0000 | 0.9444 | 0.9167 |
| F1 | 0.9774 | 0.9067 | 0.8919 |
| False-positive rate | 0.0198 | 0.0595 | 0.0595 |
| PR-AUC | 0.9962 | 0.9704 | 0.9784 |

- Training time: 16.0 ms
- Inference latency: 1.4 us/sample

## Feature Weights (standardized inputs)

| Feature | Coefficient |
|---|---:|
| packets_max | +1.5099 |
| flag_syn_ack_ratio | +0.9924 |
| duration_max | -0.9568 |
| packets_mean | +0.8804 |
| failed_auth | +0.8058 |
| failed_auth_sum | +0.8058 |
| flag_psh_ratio | +0.7808 |
| packets | +0.7203 |
| packets_sum | +0.7203 |
| rst_count_sum | +0.7190 |
| rst_count | +0.7190 |
| ack_count | +0.7129 |
| ack_count_sum | -0.7027 |
| bytes_max | +0.6974 |
| bytes_std | +0.5947 |
| iat_variance_max | +0.5779 |
| bytes_p90 | +0.5703 |
| bytes_mean | +0.5206 |
| bidirectional_ratio_std | +0.5055 |
| payload_size_entropy | -0.5028 |
| tcp_window_size_std | +0.4714 |
| bytes_sum | +0.4463 |
| bytes | +0.4463 |
| bidirectional_ratio_mean | -0.4138 |
| duration_std | -0.3973 |
| payload_size_p50 | +0.3648 |
| payload_size_std | -0.3565 |
| dst_port_entropy | +0.3512 |
| dst_port_wellknown_share | -0.3290 |
| dst_port_low_share | +0.3290 |
| payload_size_sum | -0.2720 |
| payload_size | -0.2720 |
| iat_mean_max | -0.2655 |
| iat_max | -0.2655 |
| source_port_nunique | +0.2439 |
| tcp_window_size_max | +0.2366 |
| syn_count_sum | +0.2329 |
| syn_count | +0.2329 |
| flow_event_count | +0.2329 |
| event_count | +0.2329 |
| packet_event_count | +0.2329 |
| ports_per_host_max | -0.2179 |
| tcp_window_size_mean | -0.2092 |
| ttl_min | +0.2073 |
| payload_size_mean | +0.2029 |
| iat_cv | -0.1914 |
| retransmission_mean | +0.1871 |
| retransmission_rate | +0.1871 |
| ttl_nunique | -0.1739 |
| ttl_std | -0.1704 |
| payload_size_p90 | +0.1660 |
| ttl_nunique_per_src | -0.1539 |
| iat_var | -0.1468 |
| iat_mean_var | -0.1468 |
| duration_mean | +0.1301 |
| duration | +0.1301 |
| ttl_var | -0.1286 |
| ttl_mean | +0.1104 |
| frag_df_share | +0.1071 |
| tcp_flags_nunique | -0.1059 |
| iat_mean_p90 | -0.1009 |
| iat_p90 | -0.1009 |
| retransmission_sum | +0.0984 |
| retransmission_count | +0.0984 |
| iat_mean_mean | -0.0948 |
| iat_mean | -0.0948 |
| tcp_window_size_min | +0.0898 |
| dst_port_nunique | +0.0861 |
| destination_port_nunique | +0.0861 |
| rst_count_mean | +0.0476 |
| flag_rst_ratio | +0.0476 |
| src_port_ephemeral_share | -0.0402 |
| iat_min | +0.0347 |
| iat_mean_min | +0.0347 |
| frag_offset_nunique | -0.0288 |
| iat_variance_mean | +0.0271 |
| dst_port_sequential_score | +0.0057 |
| flag_no_ack_share | +0.0047 |
| ack_count_mean | -0.0047 |
| flag_ack_ratio | -0.0047 |
| dst_port_randomness | +0.0042 |
| urg_count_mean | +0.0000 |
| protocol_nunique | +0.0000 |
| proto_udp_share | +0.0000 |
| proto_tcp_share | +0.0000 |
| proto_icmp_share | +0.0000 |
| ttl_max | +0.0000 |
| syn_count_mean | +0.0000 |
| urg_count_sum | +0.0000 |
| high_port_ratio | +0.0000 |
| flag_urg_ratio | +0.0000 |
| flag_syn_ratio | +0.0000 |
| frag_mf_share | +0.0000 |
| flag_xmas_share | +0.0000 |
| external_destination_count | +0.0000 |
| flag_fin_ratio | +0.0000 |
| fin_count_mean | +0.0000 |
| fin_count_sum | +0.0000 |

## Interpretation

- `n/a` marks a metric that is undefined for the split (for example, no positives or no predicted positives); it is not zero.
- The baseline sees one window and cannot express ordering; it is a reference, not a forecast.
- Results describe the evaluated dataset and split only. Dataset identity and licensing must be recorded alongside this report before any external claim.
