# Temporal Model Report

## Experiment Identity

- Feature version: state-features-v1
- Split strategy: scenario-held-out (same as baseline)
- Model version: gru-temporal-v1
- Horizons evaluated: 1, 2, 3, 4, 5
- Configuration: `{"hidden_size":32,"num_layers":1,"dropout":0.1,"learning_rate":0.001,"batch_size":32,"max_epochs":12,"early_stopping_patience":10}`
- Runtime: python=3.12.13, torch=2.14.0+cpu, numpy=2.5.3, platform=Linux-7.0.0-34-generic-x86_64-with-glibc2.43

### Horizon +1

- Best epoch: 1
- Training time: 2007.0 ms
- Model SHA-256: `590f5421d15d55537fec74960496f0232fa83f95ed90d9a032a789800646daf0`

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.4627 | 0.4857 | 0.1207 |
| Recall | 0.6814 | 0.1115 | 0.3111 |
| F1 | 0.5511 | 0.1813 | 0.1739 |
| False-positive rate | 0.2028 | 0.0711 | 0.1273 |
| PR-AUC | 0.6761 | 0.4444 | 0.2022 |

### Horizon +2

- Best epoch: 1
- Training time: 1851.4 ms
- Model SHA-256: `3e9565be82b9de1119739900591e1bd1b1182bcbac84602399a6112390d20c90`

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.4201 | 0.4554 | 0.1132 |
| Recall | 0.7376 | 0.1689 | 0.4091 |
| F1 | 0.5353 | 0.2464 | 0.1773 |
| False-positive rate | 0.2613 | 0.1213 | 0.1774 |
| PR-AUC | 0.6740 | 0.4337 | 0.2283 |

### Horizon +3

- Best epoch: 2
- Training time: 2040.1 ms
- Model SHA-256: `d9aeb7752d8668ef3cd7d4d42675cf3d44fd026c422b19b630ff1e162bf0e323`

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.5624 | 0.5034 | 0.1409 |
| Recall | 0.8063 | 0.2483 | 0.4884 |
| F1 | 0.6626 | 0.3326 | 0.2187 |
| False-positive rate | 0.1617 | 0.1457 | 0.1622 |
| PR-AUC | 0.7704 | 0.4723 | 0.2659 |

### Horizon +4

- Best epoch: 2
- Training time: 2185.4 ms
- Model SHA-256: `5ef07c18a2c730f1e699fa237bd8c798a17588667bedb6928352ecbfd8bf6a6a`

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.5444 | 0.5000 | 0.1519 |
| Recall | 0.8040 | 0.2313 | 0.5714 |
| F1 | 0.6492 | 0.3163 | 0.2400 |
| False-positive rate | 0.1740 | 0.1363 | 0.1711 |
| PR-AUC | 0.7624 | 0.4603 | 0.2816 |

### Horizon +5

- Best epoch: 1
- Training time: 1837.0 ms
- Model SHA-256: `554d3dc414fa9e4c626087db9e17bf9881285345110e400763924b5be657f83f`

| Metric | train | validation | test |
|---|---:|---:|---:|
| Precision | 0.4426 | 0.4598 | 0.1259 |
| Recall | 0.7145 | 0.1379 | 0.4146 |
| F1 | 0.5466 | 0.2122 | 0.1932 |
| False-positive rate | 0.2332 | 0.0946 | 0.1519 |
| PR-AUC | 0.6578 | 0.4158 | 0.2343 |

## Interpretation

- Each horizon trains an independent GRU on the same data with a different target window.
- The full timeline is not a recursive rollout; it is a multi-horizon prediction.
- Results describe the evaluated dataset and split only.
