# Architecture Submission Draft

## Problem

Static intrusion classifiers inspect isolated events and miss the direction of a multi-stage attack.

## Solution

Trajectory combines flow and PCAP-derived packet features into timestamped network states. A temporal state-transition model learns how behaviour evolves, rolls forward K windows, estimates infiltration probability, predicts an attack stage, and exposes evidence.

## Data Flow

```text
CSV/PCAP -> feature extraction -> time windows -> temporal model
        -> K-step rollout -> stage/evidence -> offline analyst UI
```

## Validation

The proposed model is compared with logistic regression using scenario-safe splits, precision, recall, F1, false-positive rate, calibration, and forecast lead time.

## Safety

The system is offline-first, reports uncertainty, documents limitations, and does not automatically block traffic.
