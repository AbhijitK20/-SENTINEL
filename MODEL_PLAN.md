# Model Plan

## Problem Formulation

Given an ordered sequence of observed network states `S(t-n+1)...S(t)`, learn a transition function that estimates future state and infiltration progression over K windows.

## Baseline

Logistic regression uses the current-window feature representation to predict the documented target. It establishes a static reference using the same eligible features and evaluation split.

## Proposed Model

Start with a GRU or LSTM sequence model because it is feasible to train, inspect, and explain within the prototype timeline. The model may have separate heads for:

- next-state reconstruction or prediction;
- infiltration probability;
- attack-stage distribution;
- optional affected-entity scoring.

## Rollout

At inference, the predicted next state is fed back into the model for K steps, with uncertainty and model version retained. If recursive error becomes excessive, the interface must display a warning rather than hide it.

## Generalization

Use scenario-held-out validation. Test whether the model can identify trajectory patterns that are not exact copies of training signatures. Report limitations when the data does not support a strong unseen-pattern claim.

## Training Controls

- Fixed seed and configuration
- Training-only normalization
- Class imbalance handling documented
- Early stopping and checkpoint selection documented
- Model artifact checksum recorded

## Model Selection

Select based on forecast quality, lead time, calibration, false positives, explanation availability, and runtime, not F1 alone.
