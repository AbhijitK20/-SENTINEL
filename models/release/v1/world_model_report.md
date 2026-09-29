# World Model Report

## Experiment Identity

- Model version: `world-model-rssm-v1`
- Core: `lstm` (hidden 64, latent 16, layers 1)
- Observation dim: 98 · sequence length: 8
- Stage vocabulary: Benign, Lateral Movement, Reconnaissance
- Feature version: state-features-v2
- Best epoch: 12 · training time: 6.3 s
- Model SHA-256: `c3fdb3ae073fe651e881fb7c0b265bdf93fbd0cd33f4f08a1ed340400af5479b`
- Configuration: `{"core_type":"lstm","hidden_size":64,"latent_dim":16,"num_layers":1,"num_heads":4,"learning_rate":0.003,"weight_decay":0.00001,"batch_size":32,"max_epochs":40,"early_stopping_patience":12,"grad_clip":5.0,"kl_free_nats":1.0,"kl_anneal_epochs":8,"risk_loss_weight":1.0,"stage_loss_weight":0.5,"imagination_samples":64,"rollout_steps":3,"rollout_loss_weight":1.0,"imagined_risk_weight":0.0}`

## Split Metrics

| Split | Windows | Recon MSE | KL (nats) | F1 | FPR | PR-AUC | Stage acc | Stage macro-F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| train | 351 | 0.4047 | 0.0645 | 0.9251 | 0.0314 | 0.9902 | 0.9580 | 0.9453 |
| validation | 113 | 0.4876 | 0.0664 | 0.7922 | 0.0365 | 0.8894 | 0.9071 | 0.8902 |
| test | 114 | 0.4110 | 0.0712 | 0.8256 | 0.0949 | 0.9185 | 0.8805 | 0.8771 |

## Open-Loop State Prediction (per step, imagined vs realized)

| Step | World model MAE | Persistence MAE | Skill |
|---:|---:|---:|---:|
| +1 | 0.4443 | 0.3465 | -0.282 |
| +2 | 0.4570 | 0.5208 | +0.122 |
| +3 | 0.4903 | 0.5812 | +0.156 |

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
