# Product Requirements Document

## 1. Overview

Trajectory is an offline analyst tool for forecasting network attack progression from traffic telemetry. It is designed for SIH26153 and targets enterprise and Critical Information Infrastructure security operations.

## 2. Users

The primary user is a SOC analyst investigating whether current activity is moving toward an infiltration stage. Secondary users are incident responders, security administrators, and evaluators.

## 3. User Problem

Analysts receive many alerts but lack a compact, evidence-backed view of where a suspicious network trajectory may go next. Static classifiers cannot represent temporal progression or provide a useful forecast horizon.

## 4. Goals

- Make future attack progression visible.
- Make the forecast technically defensible.
- Make the evidence understandable to a human analyst.
- Make the result reproducible and offline.

## 5. Non-goals

- Replace an IDS, SIEM, firewall, or EDR.
- Automatically take disruptive response actions.
- Claim universal performance across unseen networks.
- Treat feature attribution as proof of causation.

## 6. Core Workflow

1. User supplies a CSV, PCAP, or prepared replay.
2. Pipeline validates and extracts flow and packet-level features.
3. Events are normalized into timestamped windows.
4. Current and historical states are shown.
5. Model rolls forward K windows.
6. UI shows infiltration probability, stage, affected entities, and evidence.
7. User can compare forecast with the replay outcome and benchmark results.

## 7. Functional Requirements

- Accept supported CSV flow records.
- Accept PCAP files and derive packet-level features.
- Build unified timestamped feature windows.
- Train and run a logistic-regression baseline.
- Train and run a temporal state-transition model.
- Perform K-step forward simulation.
- Produce a probability timeline.
- Produce attack-stage predictions.
- Map predictions to MITRE ATT&CK-oriented vocabulary.
- Show driving features and supporting events.
- Show affected hosts or entities when available.
- Operate without cloud API dependencies.
- Export a prediction report.

## 8. Non-functional Requirements

- Reproducible commands and fixed configuration.
- Clear validation errors for malformed input.
- No secrets or private telemetry committed.
- Deterministic demo replay.
- Reasonable local inference latency for demo-sized data.
- Model and dataset limitations documented.

## 9. MVP Acceptance Criteria

The MVP is acceptable when a clean local environment can run one documented command to process demo data and display a forecast timeline containing probability, stage, evidence, and affected entities. A benchmark report must compare the temporal model and logistic regression using a leakage-safe split.

## 10. Future Scope

Temporal graph modelling, live SIEM connectors, calibration improvements, broader attack-stage ontology, and controlled response recommendations may follow the SIH prototype.
