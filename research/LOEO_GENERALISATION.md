# Leave-one-attack-out on real CIC-IDS2017

Every other real-data benchmark in this repo answers "how well does the model do
on traffic shaped like its training set". SIH26153 asks a harder question: can
the model flag an attack stage it has never seen? This is the number for that
question, and it is the one a chronological split cannot fake.

Produced by `scripts/run_loeo_benchmark.py`. The JSON artefact lands in
`reports/generated/loeo/loeo.json` (gitignored). Re-run:

```bash
uv run python scripts/run_loeo_benchmark.py \
    --data-dir data/raw/cic-ids2017/TrafficLabelling \
    --output reports/generated/loeo
```

Dataset used under its published research terms with the required citation
(Sharafaldin, Lashkari & Ghorbani, ICISSP 2018). No data is committed.

## Protocol

Per held-out stage S:

- **TRAIN** benign + every attack stage except S. S appears nowhere, in any form.
- **THRESHOLD** calibrated on a chronological slice of TRAIN only.
- **TEST** benign + S.

The holdout is by label, so no window of S reaches feature statistics, the
classifier, or the threshold. `tests/test_loeo_benchmark.py` asserts the
exclusion directly rather than inferring it from the metrics.

983 windows total (698 Benign, 285 attack) from all eight day CSVs, 300 s
windows at 150 s stride. Binary infiltration target, L2 logistic baseline,
balanced class weights, seed 42, trained on 70% of each fold's TRAIN with the
remaining 30% used only for threshold selection.

## Result

| Held-out stage | windows | AUC | detection @ train threshold | detection @ oracle threshold | benign FPR |
|---|---|---|---|---|---|
| Lateral Movement | 28 | **0.780** | 60.7% | 64.3% | 0.7% |
| Credential Access | 58 | 0.772 | 6.9% | 29.3% | 1.1% |
| Reconnaissance | 24 | 0.754 | 41.7% | 41.7% | 4.4% |
| Command and Control | 84 | 0.600 | 7.1% | 14.3% | 2.9% |
| Denial of Service | 53 | 0.564 | 0.0% | 34.0% | 0.1% |
| Initial Access | 38 | **0.401** | 0.0% | 0.0% | 0.0% |

**Mean unseen-stage AUC: 0.645.** Mean detection at the train-calibrated
threshold: 19.4%. Worst benign FPR across folds: 4.4%.

Read the AUC column, not the detection column. The train-calibrated threshold is
miscalibrated for unseen stages — balanced class weights push benign scores
high, so the 5%-FPR cut lands at 0.978 on the DoS fold when that fold's best
attack window scores 0.897, and at exactly 1.000 on Initial Access where nothing
can pass at all. The oracle column thresholds on the *test* benign scores and is
therefore **not a deployable operating point**; it exists only to bound what any
threshold choice could have achieved. Reporting the 0.0% figures without the AUC
would be reporting a calibration artifact rather than a capability.

## What the numbers mean

**Lateral Movement and Credential Access generalise best (AUC 0.78).** Beaconing
and burst data transfer leave durable flow-level traces, so a model that has
seen other attacks can still recognise them.

**Denial of Service is weak (0.564) and that is counter-intuitive.** DoS is
volumetric and should be the easiest stage to spot. The likely cause is
representation: the folds that produce positives are dominated by small web and
lateral attacks, so the classifier learns that high volume means *normal*
downloads. A volumetric flood then resembles a busy period. This is a feature-
representation problem, not a capacity problem.

**Initial Access is below chance (AUC 0.401).** On CIC-IDS2017 these are Web
Attack – brute force / XSS / SQL injection. They are HTTP-layer events, and the
flow CSVs carry no HTTP fields. In flow space a web attack is a handful of
ordinary-looking requests, so the model correctly finds nothing anomalous —
there is nothing anomalous to find. This fold is a statement about the data, not
only about the model, and no amount of retraining on these CSVs will change it.

**Command and Control (0.600) is limited by the same gap.** Heartbleed and Bot
are a few HTTPS flows among thousands inside a 300 s window.

## Scope

This measures **single-window detection of an unseen stage**, not K-step
forecasting of an unseen attack chain, and it exercises the window classifier
rather than the full nine-rule detector suite — `scripts/validate_real_detectors.py`
covers the rules. The RSSM and the rollout transition model are not in this
path, so 0.645 is a floor for the forecasting claim, not a measurement of the
world model.

## Honest summary

On real traffic, this model has weak but genuine signal on attack stages it has
never seen (AUC 0.645 against a 0.5 baseline), and it fails outright on the
stage whose evidence the dataset does not contain. Any claim of generalisation
to unseen attack patterns should be quoted at this number or lower, not at the
in-distribution scores, which are near-ceiling because the same stages appear on
both sides of the chronological split.
