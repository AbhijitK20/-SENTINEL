# World Model Report

## Experiment Identity

- Model version: `world-model-rssm-v1`
- Core: `gru` (hidden 64, latent 16, layers 1)
- Observation dim: 67 · sequence length: 8
- Stage vocabulary: Benign, Command and Control, Credential Access, Denial of Service, Initial Access, Lateral Movement, Reconnaissance
- Feature version: state-features-v1
- Best epoch: 13 · training time: 40.0 s
- Model SHA-256: `a0b75ac6674ca2fb57afba1b646473f73f121ae9fdfcd591e73f5b432b0908cb`
- Configuration: `{"core_type":"gru","hidden_size":64,"latent_dim":16,"num_layers":1,"num_heads":4,"learning_rate":0.003,"weight_decay":0.00001,"batch_size":32,"max_epochs":40,"early_stopping_patience":12,"grad_clip":5.0,"kl_free_nats":1.0,"kl_anneal_epochs":10,"risk_loss_weight":1.0,"stage_loss_weight":0.5,"imagination_samples":64,"rollout_steps":3,"rollout_loss_weight":1.0,"imagined_risk_weight":0.0}`

## Split Metrics

| Split | Windows | Recon MSE | KL (nats) | F1 | FPR | PR-AUC | Stage acc | Stage macro-F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| train | 3005 | 0.1244 | 0.1841 | 0.8876 | 0.0512 | 0.9832 | 0.9559 | 0.7973 |
| validation | 817 | 0.1059 | 0.1530 | 0.3451 | 0.0870 | 0.5359 | 0.6434 | 0.2751 |
| test | 853 | 0.1715 | 0.1929 | 0.3655 | 0.1241 | 0.4023 | 0.8897 | 0.3272 |

## Open-Loop State Prediction (per step, imagined vs realized)

| Step | World model MAE | Persistence MAE | Skill |
|---:|---:|---:|---:|
| +1 | 0.2343 | 0.1398 | -0.676 |
| +2 | 0.2537 | 0.2811 | +0.098 |
| +3 | 0.2654 | 0.2841 | +0.066 |

## Interpretation

- The reconstruction term is what makes the latent a state model: the
  decoder must explain the telemetry, not just the label.
- KL is reported in nats. A KL near zero means the prior, which never sees
  the observation, already predicts the posterior that does — that is the
  condition for open-loop imagination to be a simulation.
- Skill is 1 - model error / persistence error on standardized state
  features. Positive means open-loop simulation beats repeating the last
  window; negative means it does not, and the number is reported either way.
- Risk and stage metrics come from the heads at the observed windows;
  open-loop behaviour is the table above and the imagination benchmark.
- Results describe the evaluated dataset and split only.
