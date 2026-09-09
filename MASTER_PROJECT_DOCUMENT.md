# Trajectory

## Master Project Document

**AI-Based Network Attack Forecasting from Network Traffic Data**  
**SIH Problem Statement:** SIH26153  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Project status:** Planning complete, implementation pending

> **Trajectory is an offline, explainable temporal cyber-defence system that learns how network behaviour evolves, forecasts likely attack progression before compromise is complete, identifies potentially affected assets, and shows the evidence behind every forecast.**

This document is the project’s central reference. It explains what we are building, why it matters, how it will work, how it will be evaluated, and what must be delivered for SIH. Detailed specialist documents remain the source of truth for individual areas and are linked throughout this document.

---

## 1. Executive Summary

Traditional intrusion-detection systems commonly inspect traffic records independently and produce a current-state label such as `benign` or `malicious`. That approach can miss the direction of an attack. Reconnaissance, port probing, authentication anomalies, and new internal connections may appear harmless in isolation while forming a dangerous sequence when viewed over time.

Trajectory addresses this gap by treating network behaviour as an evolving trajectory rather than a collection of unrelated flows.

The system will:

1. Ingest network flow records, PCAP files, and supported security telemetry.
2. Extract flow-level and packet-level features.
3. Aggregate events into ordered, timestamped network states.
4. Learn state-transition dynamics from historical sequences.
5. Roll the model forward for multiple future time windows.
6. Estimate the probability of infiltration progression.
7. Predict a likely attack stage using a documented MITRE-oriented vocabulary.
8. Identify relevant hosts, users, servers, or connections.
9. Explain which observed features and events support the forecast.
10. Present the result through a fully offline analyst interface.

The core technical claim is deliberately precise:

> Given a sequence of observed network states, the model estimates the likely future trajectory and provides earlier, explainable decision support than a static current-window classifier.

We will test this claim against a logistic-regression baseline using scenario-safe evaluation. We will measure not only classification quality, but also forecast lead time, stage prediction quality, calibration, false positives, and explanation availability.

---

## 2. Official Problem Alignment

### 2.1 Problem Statement

- **ID:** `26153`
- **Title:** AI based Network Attack Forecasting from Network Traffic Data
- **Organization:** National Technical Research Organisation
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Official listing:** https://sih.gov.in/sih2026PS

### 2.2 What The PS Requires

The solution must move beyond static intrusion classification and should:

- Learn network behaviour from traffic telemetry.
- Represent network state as feature vectors or graphs.
- Learn state-transition dynamics using suitable AI methods.
- Forecast future network states.
- Estimate attacker or infiltration progression.
- Map behaviour to recognised attack stages such as MITRE ATT&CK phases.
- Provide interpretable decision support.
- Support flow records, packet captures, authentication logs, or equivalent telemetry.
- Demonstrate applicability to enterprise and Critical Information Infrastructure environments.
- Provide a software prototype, reproducible training assets, offline demonstration, and benchmark comparison against logistic regression.

### 2.3 Direct Traceability

| PS expectation | Trajectory response | Planned evidence |
|---|---|---|
| Evolving network behaviour | Timestamped network-state sequences | State-builder output and temporal model |
| Feature vector or graph | Global state vector plus entity context graph | State contract and architecture |
| State transitions | GRU/LSTM transition model | Training and rollout results |
| Flow-level features | NetFlow/IPFIX-style ingestion | Flow feature extraction tests |
| Packet-level features | PCAP parser and packet aggregation | PCAP feature coverage report |
| Future-state forecast | Recursive K-step simulation | Forecast timeline |
| Infiltration probability | Per-window probability output | Prediction contract |
| Attack-stage mapping | Documented MITRE-oriented stage mapper | Stage output and mapping plan |
| Interpretability | Attribution plus evidence extraction | Explanation panel |
| Generalization | Scenario-held-out evaluation | Split manifest and benchmark |
| Offline operation | Local training and inference | Offline acceptance test |
| Logistic baseline | Same-data static baseline | Benchmark report |
| Working prototype | Local analyst interface and replay | Demo recording |

The full requirement matrix is maintained in [`REQUIREMENTS.md`](REQUIREMENTS.md).

---

## 3. Product Vision And Positioning

### 3.1 Vision

Enable defenders to move from retrospective alert handling to evidence-backed, forward-looking cyber defence.

### 3.2 Product Positioning

> Existing security tools describe what happened. Trajectory estimates what is likely to happen next, which assets may be affected, and why the system believes that.

### 3.3 What Trajectory Is Not

Trajectory is not:

- A replacement for an IDS, SIEM, firewall, EDR, or SOC.
- A generic cybersecurity chatbot.
- A binary classifier presented as a world model.
- An automatic network-blocking system.
- A guarantee of zero-day detection.
- A proof that an attributed feature caused an attack.

### 3.4 Product Principles

1. **Forecast, do not overclaim:** probabilities are estimates, not certainty.
2. **Evidence with every prediction:** no unexplained risk number in the final product.
3. **Observed versus predicted:** the interface must make this distinction obvious.
4. **Offline by default:** runtime must not depend on cloud APIs.
5. **Analyst-controlled:** the prototype recommends investigation and does not take disruptive action.
6. **Reproducible by design:** data version, feature version, configuration, split, and model artifact are recorded.
7. **Unknown is valid:** insufficient evidence must be represented explicitly instead of forced into a confident stage.

The broader positioning and differentiation are described in [`VISION_AND_POSITIONING.md`](VISION_AND_POSITIONING.md).

---

## 4. The Problem We Solve

### 4.1 Current Limitation

An isolated-flow classifier may see:

```text
Flow 1 → benign
Flow 2 → suspicious
Flow 3 → benign
Flow 4 → malicious
```

But an analyst may need to understand:

```text
New destination discovery
        ↓
Port probing
        ↓
Authentication anomalies
        ↓
New internal connections
        ↓
Likely lateral movement
```

The sequence, timing, and relationships are part of the threat signal.

### 4.2 User Pain

SOC analysts and incident responders need to answer:

- What is happening now?
- Is this behaviour moving toward compromise?
- What is likely to happen next?
- Which host, account, or server may be affected?
- How soon might the next stage occur?
- Why does the model believe this?
- How reliable is the evidence?

### 4.3 Product Opportunity

Trajectory adds a predictive intelligence layer above existing telemetry sources. It does not need to replace current controls; it uses their data to give analysts temporal context and a forward-looking hypothesis.

---

## 5. Users And Use Cases

### 5.1 Primary User: SOC Analyst

**Goal:** Prioritize investigations and decide what to inspect next.

**Needs:**

- Current network state
- Probability timeline
- Likely next stage
- Affected entities
- Supporting evidence
- Confidence and coverage warnings

**Success:** Understands and validates a forecast within one minute.

### 5.2 Secondary User: Incident Responder

**Goal:** Reconstruct progression and prioritize containment analysis.

**Needs:**

- Observed-versus-predicted timeline
- Entity relationships
- Forecast path
- Exportable report

### 5.3 Secondary User: CII Security Operator

**Goal:** Monitor important systems without sending sensitive telemetry outside the environment.

**Needs:**

- Offline processing
- Asset prioritization
- Uncertainty reporting
- Audit-friendly output

### 5.4 Evaluator: SIH Judge

**Goal:** Determine whether the project solves forecasting rather than merely detecting.

**Needs:**

- Clear technical distinction
- Working K-step rollout
- Explainability
- Baseline comparison
- Reproducible demo

### 5.5 Core Use Cases

1. Upload and analyze a supported CSV.
2. Upload and parse a PCAP.
3. Replay a deterministic attack trajectory.
4. Inspect the current network state.
5. View predicted future states.
6. Review likely attack stage and affected assets.
7. Inspect driving features and supporting events.
8. Compare predicted progression with replay reality.
9. Review baseline versus temporal-model metrics.
10. Export an analyst-readable report.

Detailed personas and journeys are in [`USER_PERSONAS.md`](USER_PERSONAS.md) and [`USER_JOURNEYS.md`](USER_JOURNEYS.md).

---

## 6. Proposed Solution

### 6.1 High-Level Flow

```text
CSV flows / PCAP / replay data
              ↓
      Ingestion and validation
              ↓
    Unified timestamped events
              ↓
       Time-window state builder
              ↓
     Ordered network-state sequence
              ↓
     Temporal transition model
              ↓
        K-step future rollout
              ↓
 ┌────────────┬──────────────┬───────────────┐
 │ Risk       │ Attack stage │ Evidence      │
 │ timeline   │ prediction   │ and assets    │
 └────────────┴──────────────┴───────────────┘
              ↓
       Offline analyst interface
```

### 6.2 What The Analyst Sees

```text
CURRENT OBSERVATION
Workstation-17 is contacting many new internal destinations.

FORECAST
Initial Access: 76%
Lateral Movement: 58% within the next 3 windows

LIKELY AFFECTED ENTITY
Server-03

SUPPORTING EVIDENCE
- Destination diversity increased 4.2x.
- Failed authentication rate increased.
- New internal connections appeared after reconnaissance.
```

The exact values above are illustrative presentation content, not measured results. Final demo numbers must come from the implemented model.

### 6.3 Innovation

The novelty is the combined product of:

- Temporal network-state modelling
- Forward simulation instead of only current-window classification
- Stage and asset context
- Evidence attached to every forecast
- Offline, reproducible operation
- Evaluation centered on warning lead time, not accuracy alone

The project should not claim that any one component is individually novel. The innovation claim is the integrated, practical, explainable forecasting workflow aligned to the SIH problem.

---

## 7. Detailed Technical Approach

### 7.1 Input Sources

The supported input modes are:

1. **Flow CSV:** NetFlow/IPFIX-style records or compatible prepared datasets.
2. **PCAP:** Raw packet captures parsed locally.
3. **Prepared replay:** Deterministic data for the judge-facing demo.
4. **Future extension:** Authentication logs and other security telemetry with an explicit adapter.

The system must report which feature levels are available for each input. It must never silently pretend that packet-level evidence exists when the input contains only flow records.

### 7.2 Flow-Level Features

Required conceptual feature families:

- Source and destination identifiers
- Source and destination ports
- Protocol
- TCP flag bitmask and flag counts
- Bytes transferred
- Packets per flow
- Flow duration
- Inter-arrival-time mean, variance, and maximum
- Bidirectional flow ratio
- Flow counts per entity and destination
- Destination diversity and port diversity
- Burst and rate statistics

### 7.3 Packet-Level Features

Required conceptual feature families:

- TTL values and session-level TTL variance
- TCP window-size statistics
- IP fragmentation flags
- Payload-size distribution summaries
- Sequential or randomized port-scan patterns
- Retransmission counts
- Packet timing and ordering summaries

Payload content should not be required for the initial prototype. Encrypted or unavailable payloads must be represented as a coverage limitation.

### 7.4 Unified Event Layer

All supported inputs are normalized into a common event representation containing:

- Event timestamp
- Source and destination entities
- Event type and source format
- Feature values
- Session or flow identity when available
- Provenance reference
- Feature availability metadata

### 7.5 Time Windows

Events are grouped into ordered windows. Each window has:

- Start and end timestamps
- Aggregated feature vector
- Entity list
- Connection or edge summary
- Input coverage
- Source event references
- Derived label or target where available

Window duration, stride, and forecast horizon must be configuration values recorded with each experiment.

### 7.6 Network State Representation

The initial model uses a structured global state vector because it is easier to validate, train, and explain within the prototype schedule.

The state may include:

```text
Active flows
Unique destinations
Port diversity
SYN / ACK / FIN / RST distributions
Bytes and packets
IAT statistics
Retransmission rate
TTL statistics
Authentication-failure rate
Internal connection rate
Entity risk summaries
```

An entity graph will support visualization and affected-asset context. A full temporal GNN remains a possible extension, not a dependency for the first working model.

### 7.7 World-Model-Style Transition Learning

The modelling objective is expressed as:

```text
P(S[t+1] | S[t])
```

In practice, the model receives a sequence:

```text
S(t-3), S(t-2), S(t-1), S(t)
```

and estimates:

- Next-state representation
- Infiltration probability
- Attack-stage distribution
- Optional affected-entity scores

The model is world-model-inspired because it learns a representation of changing network state and supports forward rollout. We will not claim a general-purpose causal world model.

### 7.8 Baseline

The logistic-regression baseline receives comparable current-window features and predicts the agreed target. It answers the static question:

```text
Is the current window associated with malicious activity?
```

The proposed temporal model answers the forward-looking question:

```text
Given the observed trajectory, what is likely to happen over future windows?
```

### 7.9 K-Step Rollout

At inference:

1. Select the current observed state sequence.
2. Predict the next state and progression probability.
3. Feed the predicted state into the next rollout step.
4. Repeat for K configured windows.
5. Produce a probability timeline and stage distribution.
6. Attach model version, input window, horizon, and warnings.

Recursive predictions can accumulate error. The UI must show the horizon and uncertainty rather than presenting distant predictions as equally reliable.

### 7.10 Attack-Stage Mapping

The initial stage vocabulary is:

- Reconnaissance
- Initial Access
- Lateral Movement
- Command and Control
- Exfiltration

Additional techniques such as Execution, Persistence, and Credential Access may be included only where data and mappings support them.

Mapping rules must:

- Distinguish observed evidence from predicted stage.
- Include confidence.
- Allow `Unknown` or `Insufficient evidence`.
- Avoid forcing a perfectly linear kill chain.
- Preserve mapping provenance and version.

### 7.11 Explainability

Each forecast should contain:

- Probability and forecast horizon
- Ranked driving features
- Direction or contribution where meaningful
- Supporting events or entities
- Coverage warnings
- Explanation method and model version

SHAP, attention, or another local attribution method may be used. The product must describe these as model evidence or association, not causal proof.

---

## 8. System Architecture

### 8.1 Component Architecture

```text
┌───────────────────────────────────────────────────────┐
│                    Offline Interface                  │
│  Upload | Replay | Forecast | Evidence | Evaluation   │
└───────────────────────┬───────────────────────────────┘
                        │
┌───────────────────────v───────────────────────────────┐
│                 Inference Orchestrator                │
└───────────────┬───────────────────────┬───────────────┘
                │                       │
┌───────────────v────────────┐  ┌───────v──────────────┐
│ CSV / PCAP Ingestion        │  │ Saved Model Artifacts │
└───────────────┬────────────┘  └───────┬──────────────┘
                v                       v
┌───────────────────────────────────────────────────────┐
│      Feature Extraction, Validation, Normalization    │
└───────────────────────┬───────────────────────────────┘
                        v
┌───────────────────────────────────────────────────────┐
│             Timestamped State Construction             │
└───────────────────────┬───────────────────────────────┘
                        v
┌───────────────────────────────────────────────────────┐
│       Temporal Model + Stage Head + Evidence Layer     │
└───────────────────────┬───────────────────────────────┘
                        v
┌───────────────────────────────────────────────────────┐
│ Probability | Stage | Entities | Evidence | Warnings  │
└───────────────────────────────────────────────────────┘
```

### 8.2 Operating Modes

- **Training:** prepare data, train baseline and temporal model, evaluate, export artifacts.
- **Batch inference:** analyze an uploaded CSV or PCAP.
- **Replay:** advance through a deterministic scenario window by window.
- **Evaluation:** regenerate metrics and compare observed outcomes with forecasts.

### 8.3 Proposed Technology Stack

| Area | Technology direction |
|---|---|
| Language | Python |
| Data | Pandas, NumPy |
| Classical ML | Scikit-learn |
| Deep learning | PyTorch |
| PCAP parsing | Scapy or PyShark |
| Interface | Streamlit or Flask |
| Graph context | NetworkX, Plotly |
| Configuration | YAML or TOML |
| Environment | `uv`-managed Python environment |
| Runtime | Local/offline |

The final stack is subject to a Sprint 0 decision after environment validation.

Full architecture details are in [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 9. Data Strategy

### 9.1 Candidate Datasets

- CIC-IDS2017/2018
- CTU-13
- UNSW-NB15
- CICIoT2023
- LANL Authentication Dataset
- DARPA Intrusion Detection datasets

### 9.2 Selection Criteria

The primary dataset must have, as far as possible:

- Timestamps
- Stable scenario, session, or campaign identity
- Benign context
- Attack labels
- Enough sequence structure to derive future targets
- Documented access and licensing

A secondary dataset should test whether behaviour learned from one source transfers beyond that source.

### 9.3 Combined Feature Requirement

The PS requires both flow-level and packet-level features. The implementation must support:

```text
CSV only       → flow features available, packet coverage warning
PCAP only      → packet and derived flow features
CSV + PCAP     → combined features only when alignment is defensible
```

We must never join unrelated CSV and PCAP rows merely to satisfy a checklist. Every combined representation needs a documented alignment rule.

### 9.4 Label Strategy

Binary labels, future-state targets, and attack-stage targets must be separately defined. Stage labels may be derived from dataset annotations and documented rules. If the dataset cannot support reliable stage ground truth, that limitation must be visible in the evaluation.

### 9.5 Leakage Controls

- Split by scenario, campaign, day, or source.
- Do not split adjacent windows from one attack into train and test arbitrarily.
- Do not aggregate future events into a current state.
- Fit normalization only on training data.
- Exclude labels, future stage names, and scenario IDs from unintended features.
- Record the split manifest.

Detailed decisions belong in [`DATASET_PLAN.md`](DATASET_PLAN.md) and [`FEATURE_SPECIFICATION.md`](FEATURE_SPECIFICATION.md).

---

## 10. Prediction Contract

Every forecast must be serializable into a stable structure similar to:

```json
{
  "input_window": {
    "start": "timestamp",
    "end": "timestamp"
  },
  "horizon_windows": 3,
  "model_version": "trajectory-model-version",
  "probability_timeline": [
    {
      "window": 1,
      "infiltration_probability": 0.0,
      "confidence": 0.0
    }
  ],
  "predicted_stage": {
    "name": "Lateral Movement",
    "probability": 0.0,
    "confidence": "medium"
  },
  "affected_entities": [],
  "driving_features": [
    {
      "name": "destination_diversity",
      "contribution": 0.0,
      "direction": "increasing"
    }
  ],
  "supporting_events": [],
  "coverage": {
    "flow_features": true,
    "packet_features": true
  },
  "warnings": []
}
```

Rules:

- Observed and predicted timestamps must be distinct.
- Horizon and model version are mandatory.
- Probabilities must be valid and calibrated or clearly labelled as raw scores.
- Missing evidence must produce a warning.
- Explanation fields must not be fabricated.

The complete contract is maintained in [`DATA_CONTRACTS.md`](DATA_CONTRACTS.md).

---

## 11. Evaluation Strategy

### 11.1 Baseline Comparison

Both systems must use comparable features and the same evaluation data:

```text
Static baseline:
Current window → Logistic Regression → current attack target

Proposed model:
State sequence → Temporal model → future state/progression forecast
```

### 11.2 Required Metrics

- Precision
- Recall
- F1 score
- False-positive rate
- PR-AUC where appropriate
- Stage prediction accuracy or macro-F1
- Forecast calibration
- Inference latency
- Median and distribution of forecast lead time

### 11.3 Forecast Lead Time

The central product metric is how early the system makes a useful forecast before the target stage becomes observable. The evaluation must define:

- What counts as the target stage becoming observable.
- What horizon counts as a correct forecast.
- How early warnings are measured.
- How false early warnings are counted.

These rules must be fixed before final benchmarking.

### 11.4 Generalization

Scenario-held-out evaluation is required for a credible generalization claim. We should not say “works on unseen attacks” unless the split and result actually support that statement.

### 11.5 Results Reporting

Every result must include:

- Dataset and version
- Feature version
- Split strategy
- Random seed
- Model configuration
- Metric values
- Failure cases
- Coverage limitations
- Runtime details

The evaluation procedure is defined in [`EVALUATION_PLAN.md`](EVALUATION_PLAN.md), with final values recorded in [`RESULTS_TEMPLATE.md`](RESULTS_TEMPLATE.md).

---

## 12. Feasibility, Risks, And Mitigation

| Risk | Consequence | Mitigation |
|---|---|---|
| Imbalanced attacks | Rare progression missed | Class weighting, PR metrics, scenario analysis |
| Dataset mismatch | Weak real-world transfer | Secondary dataset and limitations |
| Temporal leakage | False performance | Scenario/time split and audit |
| Missing packet coverage | Partial evidence | Coverage report and warning state |
| Recursive drift | Distant rollout unreliable | Short horizon and uncertainty |
| Ambiguous stages | Misleading MITRE label | Confidence and unknown state |
| Attribution instability | False trust | Stability checks and cautious wording |
| Sensitive data | Privacy or security exposure | Local processing, anonymization, no secrets |
| Overfitting | Memorized signatures | Held-out scenarios and feature review |
| Demo failure | Poor evaluator experience | Deterministic replay and preflight check |
| Scope expansion | Incomplete core | P0-first backlog and quality gates |

### 12.1 Feasibility Position

The prototype is feasible because it can be built from public data and open-source components, run locally, and demonstrate a deterministic replay without requiring access to a live enterprise network. Production deployment would require additional validation and integration that are outside the first SIH prototype.

---

## 13. Security And Privacy

### 13.1 Data Safety

- Process telemetry locally by default.
- Never commit private captures or credentials.
- Use synthetic or redistributable demo data.
- Anonymize identifiers when practical.
- Avoid logging sensitive payload content.
- Record dataset licenses and access restrictions.

### 13.2 Prototype Safety

Trajectory does not automatically isolate hosts, block traffic, or modify firewall rules. Any future response recommendation remains analyst-controlled.

### 13.3 Threats To The System

- Poisoned telemetry
- Manipulated labels
- Data leakage
- Adversarial traffic
- Model overconfidence
- Sensitive report exposure
- Unsafe action based on a false positive

Threats and mitigations are maintained in [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`SECURITY_AND_PRIVACY.md`](SECURITY_AND_PRIVACY.md).

---

## 14. Agile Delivery Plan

### 14.1 Method

Use a lightweight Scrum/Kanban hybrid with one-week sprints:

```text
Backlog → Spike/Ready → In Progress → Review → Validation → Done
```

Every sprint must end with a demonstrable increment or a documented blocker and decision.

### 14.2 Epics

1. Foundation
2. Ingestion
3. Feature engineering
4. Network states
5. Logistic-regression baseline
6. Temporal world model
7. K-step forecasting
8. Attack-stage mapping
9. Explainability
10. Evaluation and benchmarking
11. Offline analyst interface
12. SIH submission package

### 14.3 Sprint Roadmap

| Sprint | Focus | Exit outcome |
|---:|---|---|
| 0 | Discovery and foundation | Approved planning package, dataset criteria, contracts |
| 1 | Ingestion and features | CSV/PCAP paths and feature coverage |
| 2 | States and labels | Windowed states, targets, leakage-safe splits |
| 3 | Baseline | Reproducible logistic-regression metrics |
| 4 | Temporal model | Trained transition model and artifact |
| 5 | Rollout and stages | K-step forecast and lead-time output |
| 6 | Explainability | Evidence, attribution, stage/entity context |
| 7 | Demo application | Offline interface and deterministic replay |
| 8 | Submission hardening | Final metrics and SIH materials |

### 14.4 Definition Of Done

Work is done only when:

- Acceptance criteria pass.
- Tests or manual verification exist.
- Documentation is updated.
- Reproducible commands are recorded.
- Dataset, split, seed, and model version are known for ML work.
- No unsupported claim is shown in the interface or submission material.

Backlog and story detail are maintained in [`EPICS.md`](EPICS.md), [`USER_STORIES.md`](USER_STORIES.md), [`PRODUCT_BACKLOG.md`](PRODUCT_BACKLOG.md), and [`SPRINT_PLAN.md`](SPRINT_PLAN.md).

---

## 15. Prototype Interface

### 15.1 Main Screens

1. **Input and coverage**
   - Upload CSV or PCAP.
   - Show validation and feature availability.

2. **Current network state**
   - Active flows.
   - Destination and port diversity.
   - Flag and timing statistics.
   - Entity context.

3. **Forecast timeline**
   - Current observed state.
   - K future windows.
   - Probability trend.
   - Confidence and warnings.

4. **Attack-stage view**
   - Observed stage evidence.
   - Predicted next stage.
   - Probability and confidence.

5. **Evidence view**
   - Driving features.
   - Supporting events.
   - Affected entities.
   - Explanation limitations.

6. **Evaluation view**
   - Logistic regression versus temporal model.
   - Metrics and lead time.
   - Dataset/split metadata.

7. **Replay comparison**
   - Forecast at each time.
   - What actually happened next.

### 15.2 UX Rules

- Use “observed” and “forecast” labels everywhere.
- Do not show a risk score without horizon and evidence.
- Make uncertainty visible.
- Provide readable explanations before technical details.
- Never imply automatic response.

---

## 16. Demo Story

### 16.1 Scenario

An enterprise-like network contains a suspicious workstation, an authentication service, an internal server, and benign background traffic.

### 16.2 Replay Timeline

1. Normal baseline is established.
2. Workstation-17 contacts many new destinations.
3. Port and timing patterns become abnormal.
4. Failed authentication activity increases.
5. New internal connections appear.
6. Trajectory forecasts likely lateral movement.
7. The replay reaches the next stage for comparison.

### 16.3 Two-Minute Demo

| Time | Action |
|---|---|
| 0:00–0:15 | Explain static detection versus forecasting |
| 0:15–0:35 | Start offline replay and show normal state |
| 0:35–0:55 | Show reconnaissance and state change |
| 0:55–1:15 | Show rising probability and predicted stage |
| 1:15–1:35 | Show evidence and affected entities |
| 1:35–1:50 | Compare forecast with actual next stage |
| 1:50–2:00 | Show baseline comparison and offline operation |

### 16.4 Demo Success Criteria

- Forecast appears before target-stage evidence is complete.
- Evidence names relevant patterns and entities.
- Observed and predicted values are distinct.
- The replay is deterministic.
- The spoken claim matches actual measured results.

The detailed demo package is in [`DEMO_PLAN.md`](DEMO_PLAN.md), [`DEMO_SCENARIO.md`](DEMO_SCENARIO.md), and [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md).

---

## 17. SIH Idea PPT Plan

The official idea presentation has a maximum of six slides including the title slide and must be submitted as PDF using the provided template.

### Slide 1: Idea Title

- Trajectory
- AI-Based Network Attack Forecasting from Network Traffic Data
- SIH26153, NTRO, team and institute

### Slide 2: Proposed Solution

- Static IDS limitation
- Temporal network-state solution
- K-step forecast
- Stage, assets, and evidence outputs
- Innovation statement

### Slide 3: Technical Approach

- Flow and packet features
- CSV/PCAP pipeline
- State-transition model
- Logistic baseline
- GRU/LSTM rollout
- Offline technology stack

### Slide 4: Feasibility And Viability

- Open data and open-source tools
- Offline prototype feasibility
- Risks and mitigations
- Practical MVP boundary

### Slide 5: Impact And Benefits

- SOC and CII users
- Earlier warning
- Better prioritization
- Explainable decisions
- Social, economic, and operational benefits

### Slide 6: Research And References

- Official SIH source
- Dataset sources
- MITRE ATT&CK, CAPEC, NVD, NCIIPC
- Technical research areas
- Open-source tools

The detailed, presentation-ready content is maintained in [`PRESENTATION_OUTLINE.md`](PRESENTATION_OUTLINE.md).

### PPT Rules

- Use diagrams, icons, short bullets, and data cards.
- Avoid paragraph-heavy slides.
- Do not use final metric claims before experiments exist.
- Cite only verified references.
- Export PDF, not PPT or Word.
- Delete the template’s instructional slide before portal upload if required.

---

## 18. SIH Submission Package

Required deliverables:

1. Source-code link.
2. README with setup and usage.
3. Architecture document of maximum two pages.
4. Demo video of maximum two minutes.
5. Technical presentation of maximum five slides where applicable; the official idea PPT content plan in this repository follows the six-slide template specified by the team for the SIH idea submission.

Supporting evidence:

- Dataset preparation and licensing notes
- Training configuration
- Model weights
- Feature schema
- Baseline metrics
- Temporal-model metrics
- Forecast lead-time result
- Explainability example
- Offline verification
- Known limitations

Before submission, all documents, video narration, slides, and UI labels must tell the same story and use the same measured values.

The submission checklist is maintained in [`SUBMISSION_PLAN.md`](SUBMISSION_PLAN.md).

---

## 19. Quality Gates

### Gate 1: Planning Complete

Requirements, stories, backlog, architecture, data strategy, and acceptance criteria are linked.

### Gate 2: Data Ready

Feature coverage, label provenance, dataset version, contracts, and leakage controls are validated.

### Gate 3: Baseline Ready

Logistic regression runs reproducibly and produces agreed metrics.

### Gate 4: Forecasting Ready

The temporal model performs genuine K-step rollout. A static classifier cannot pass this gate.

### Gate 5: Explainability Ready

Every forecast includes evidence or an explicit explanation-unavailable state.

### Gate 6: Demo Ready

Offline replay is repeatable and the main story fits two minutes.

### Gate 7: Submission Ready

All P0 requirements have evidence and no submission claim exceeds the implemented result.

Full quality criteria are in [`QUALITY_GATES.md`](QUALITY_GATES.md), with testing in [`TEST_STRATEGY.md`](TEST_STRATEGY.md).

---

## 20. Known Limitations

- Public datasets may not represent real enterprise or CII topology.
- Attack labels may not provide complete ground-truth MITRE stage transitions.
- Flow and packet feature coverage depends on the input source.
- Recursive rollout can accumulate prediction error.
- Attribution indicates model evidence, not causality.
- Probability estimates are not certainty.
- Encrypted traffic limits payload interpretation.
- The prototype does not replace production SOC controls.
- A positive forecast is decision support, not authorization for automatic response.

These limitations are part of the project’s credibility. Hiding them would weaken the submission.

---

## 21. Future Scope

After the first SIH prototype, possible extensions include:

- Temporal graph neural network.
- Live SIEM, IDS, EDR, and cloud telemetry adapters.
- Authentication-log fusion.
- Better probability calibration.
- Expanded MITRE technique mapping.
- Cross-environment transfer learning.
- Analyst feedback loop.
- Controlled response recommendations.
- Drift detection and model monitoring.
- Privacy-preserving deployment across multiple sites.

These are future directions, not MVP commitments.

---

## 22. Definition Of Success

Trajectory is successful as an SIH prototype when a clean local environment can:

1. Accept supported CSV or PCAP demo data.
2. Produce flow and packet feature coverage information.
3. Build ordered network states.
4. Run a logistic baseline and temporal model.
5. Roll the temporal model forward for K windows.
6. Display an infiltration probability timeline.
7. Predict a documented attack stage or show insufficient evidence.
8. Identify affected entities where supported.
9. Explain the evidence behind the forecast.
10. Compare the prediction with what happened next.
11. Report benchmark metrics without leakage.
12. Run without cloud dependencies.
13. Provide the required SIH documentation and demo assets.

The strongest final claim will be measured and specific:

> **On the documented evaluation scenarios, Trajectory provided an earlier and explainable forecast of attack progression than the static baseline, while operating locally and exposing its uncertainty.**

We should use this sentence only if the final experiment supports it.

---

## 23. Supporting Documents

### Product And Requirements

- [`README.md`](README.md)
- [`PROJECT_CHARTER.md`](PROJECT_CHARTER.md)
- [`VISION_AND_POSITIONING.md`](VISION_AND_POSITIONING.md)
- [`PRD.md`](PRD.md)
- [`REQUIREMENTS.md`](REQUIREMENTS.md)
- [`USER_PERSONAS.md`](USER_PERSONAS.md)
- [`USER_JOURNEYS.md`](USER_JOURNEYS.md)

### Agile And Delivery

- [`EPICS.md`](EPICS.md)
- [`USER_STORIES.md`](USER_STORIES.md)
- [`FEATURE_CATALOG.md`](FEATURE_CATALOG.md)
- [`PRODUCT_BACKLOG.md`](PRODUCT_BACKLOG.md)
- [`AGILE_WORKFLOW.md`](AGILE_WORKFLOW.md)
- [`DEFINITION_OF_READY.md`](DEFINITION_OF_READY.md)
- [`DEFINITION_OF_DONE.md`](DEFINITION_OF_DONE.md)
- [`SPRINT_PLAN.md`](SPRINT_PLAN.md)
- [`RELEASE_PLAN.md`](RELEASE_PLAN.md)

### Technical Planning

- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`DATASET_PLAN.md`](DATASET_PLAN.md)
- [`DATA_CONTRACTS.md`](DATA_CONTRACTS.md)
- [`FEATURE_SPECIFICATION.md`](FEATURE_SPECIFICATION.md)
- [`MODEL_PLAN.md`](MODEL_PLAN.md)
- [`EXPLAINABILITY_PLAN.md`](EXPLAINABILITY_PLAN.md)
- [`MITRE_MAPPING_PLAN.md`](MITRE_MAPPING_PLAN.md)

### Quality, Security, And Evaluation

- [`EVALUATION_PLAN.md`](EVALUATION_PLAN.md)
- [`TEST_STRATEGY.md`](TEST_STRATEGY.md)
- [`QUALITY_GATES.md`](QUALITY_GATES.md)
- [`SECURITY_AND_PRIVACY.md`](SECURITY_AND_PRIVACY.md)
- [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md)
- [`RESULTS_TEMPLATE.md`](RESULTS_TEMPLATE.md)

### Demo And Submission

- [`DEMO_PLAN.md`](DEMO_PLAN.md)
- [`DEMO_SCENARIO.md`](DEMO_SCENARIO.md)
- [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md)
- [`SUBMISSION_PLAN.md`](SUBMISSION_PLAN.md)
- [`PRESENTATION_OUTLINE.md`](PRESENTATION_OUTLINE.md)
- [`ARCHITECTURE_SUBMISSION.md`](ARCHITECTURE_SUBMISSION.md)

---

## 24. Immediate Next Step

The planning package is now complete enough to begin Sprint 0 execution. The first implementation decisions should be:

1. Confirm the development environment and Python version.
2. Verify candidate dataset access and licensing.
3. Select the primary and secondary dataset.
4. Freeze the initial event and state schemas.
5. Record the first architecture decision records.
6. Set up the reproducible project environment.
7. Begin ingestion only after the data contract is approved.

No model should be trained before the dataset, labels, windowing, split strategy, and prediction contract are documented.
