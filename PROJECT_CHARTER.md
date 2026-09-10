# Project Charter

## Project

- Name: SENTINEL
- SIH problem statement: SIH26153
- Title: AI based Network Attack Forecasting from Network Traffic Data
- Organization: National Technical Research Organisation (NTRO)
- Category: Software
- Theme: Blockchain & Cybersecurity

## Purpose

Build a reproducible, fully offline software prototype that forecasts the likely progression of malicious network activity before compromise is complete.

## Vision

Help defenders move from retrospective alert handling to evidence-backed, forward-looking cyber defence.

## Objectives

1. Ingest flow records and PCAP-derived packet features.
2. Represent network behaviour as timestamped, evolving states.
3. Learn temporal state-transition dynamics rather than only static labels.
4. Roll the model forward for multiple future windows.
5. Forecast infiltration probability and likely attack stage.
6. Explain each forecast using driving traffic evidence.
7. Benchmark against logistic regression using leakage-safe evaluation.
8. Demonstrate the result through a deterministic offline replay.

## Success Criteria

- All mandatory PS requirements have an implementation and verification reference.
- A user can run the demo without cloud APIs.
- The proposed temporal model produces a probability timeline and K-step forecast.
- Flow-level and packet-level features are present in the supported pipeline.
- A logistic-regression baseline is evaluated on comparable features.
- Forecasts include stage, affected entities, evidence, and confidence.
- Source, setup, architecture, demo, and presentation materials are complete.

## Scope Boundaries

In scope: offline analysis, public datasets, CSV and PCAP input, temporal modelling, forward simulation, explainability, MITRE-oriented mapping, analyst dashboard, benchmark reporting.

Out of scope for the prototype: automatic traffic blocking, production SOC integration, live packet interception, guaranteed causal claims, cloud-hosted inference, and a general-purpose cybersecurity chatbot.

## Constraints

- Public datasets may not represent every enterprise environment.
- Attack-stage labels may require documented derivation.
- Training and inference must be reproducible on ordinary development hardware.
- The demonstration must remain understandable within two minutes.

## Stakeholders

- Primary: SOC analyst and incident responder
- Operational: enterprise or Critical Information Infrastructure security operator
- Evaluator: SIH judge and technical reviewer
- Builder: project team

## Milestones

1. Planning baseline approved
2. Data pipeline validated
3. Baseline benchmark complete
4. Temporal model and rollout working
5. Explainable forecast demo working
6. Submission package validated
