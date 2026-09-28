# World Model Report

## Experiment Identity

- Model version: `world-model-rssm-v1`
- Core: `lstm` (hidden 64, latent 16, layers 1)
- Observation dim: 98 · sequence length: 8
- Stage vocabulary: Benign, Lateral Movement, Reconnaissance
- Feature version: state-features-v1
- Best epoch: 20 · training time: 7.0 s
- Model SHA-256: `c6d7fedc87b8a83533e22219caea0ae01d9a07d85509096a27fe05f8acdcc080`
- Configuration: `{"core_type":"lstm","hidden_size":64,"latent_dim":16,"num_layers":1,"num_heads":4,"learning_rate":0.003,"weight_decay":0.00001,"batch_size":32,"max_epochs":40,"early_stopping_patience":12,"grad_clip":5.0,"kl_free_nats":1.0,"kl_anneal_epochs":8,"risk_loss_weight":1.0,"stage_loss_weight":0.5,"imagination_samples":64,"rollout_steps":3,"rollout_loss_weight":1.0,"imagined_risk_weight":0.0}`

## Split Metrics

| Split | Windows | Recon MSE | KL (nats) | F1 | FPR | PR-AUC | Stage acc | Stage macro-F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| train | 390 | 0.2776 | 0.0045 | 1.0000 | 0.0000 | 1.0000 | 0.9997 | 0.9997 |
| validation | 130 | 0.3562 | 0.0060 | 1.0000 | 0.0000 | 1.0000 | 0.9875 | 0.9876 |
| test | 130 | 0.3447 | 0.0053 | 1.0000 | 0.0000 | 1.0000 | 0.9856 | 0.9855 |

## Open-Loop State Prediction (per step, imagined vs realized)

| Step | World model MAE | Persistence MAE | Skill |
|---:|---:|---:|---:|
| +1 | 0.3116 | 0.2991 | -0.042 |
| +2 | 0.3210 | 0.4394 | +0.270 |
| +3 | 0.3517 | 0.4703 | +0.252 |

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
