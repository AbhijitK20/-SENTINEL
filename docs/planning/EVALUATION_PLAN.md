# Evaluation Plan

## Primary Comparison

Compare logistic regression and the temporal model on the same prepared data, feature availability, target definition, and leakage-safe split.

## Metrics

- Precision
- Recall
- F1 score
- False-positive rate
- PR-AUC where class imbalance makes it useful
- Forecast lead time before the next stage becomes observable
- Stage prediction accuracy or macro-F1
- Probability calibration
- Inference latency

## Split Strategy

Prefer scenario, campaign, day, or source-held-out splits. Never use random adjacent rows when temporal neighbours from the same attack could cross train and test.

## Forecast Definition

A useful forecast is one made before the target stage is observable in the current window and matched to the target within the documented horizon. Lead-time calculation and tolerance must be fixed before final evaluation.

## Required Reports

- Dataset and feature coverage
- Split and leakage audit
- Baseline metrics
- Temporal model metrics
- Lead-time distribution
- Calibration and uncertainty notes
- Failure cases and limitations
