# Trajectory: Six-Slide SIH Presentation Outline

## Submission Rules

- Maximum length: 6 slides, including the title slide
- Submission format: PDF exported from the official SIH template
- Style: point-based, visual, and readable without presenter narration
- Evidence rule: use measured results only; label all estimates and targets
- Product rule: present Trajectory as analyst decision support, not an autonomous defence system
- Final verification: confirm all registration details against the SIH portal before submission

## Core Story

```text
Existing tools detect what is happening now
                    ↓
Trajectory learns how network behaviour evolves
                    ↓
The model simulates likely future network states
                    ↓
The analyst receives an early, evidence-backed forecast
```

---

## Slide 1: Title And Registration

### Main Title

# TRAJECTORY

### Project Subtitle

## AI-Based Network Attack Forecasting from Network Traffic Data

### One-Line Positioning

**An offline, explainable temporal cyber-defence system that forecasts likely attack progression before compromise is complete.**

### Registration Block

| Field | Content |
|---|---|
| Event | Smart India Hackathon 2026 |
| Problem Statement ID | `SIH26153` |
| Problem Statement Title | AI based Network Attack Forecasting from Network Traffic Data |
| Organization | National Technical Research Organisation (NTRO) |
| Theme | Blockchain & Cybersecurity |
| PS Category | Software |
| Team ID | `[ADD OFFICIAL TEAM ID]` |
| Team Name | `[ADD OFFICIAL TEAM NAME]` |
| Institute | `[ADD OFFICIAL INSTITUTE NAME]` |

### Hero Visual

```text
NETWORK TELEMETRY  →  CURRENT STATE  →  FUTURE FORECAST  →  EARLIER RESPONSE
```

Suggested visual treatment:

- Use a dark network-grid or attack-path background.
- Place the Trajectory name and positioning statement on the left.
- Place the registration block in a compact panel on the right.
- Show one highlighted attack path moving from reconnaissance toward lateral movement.
- Keep team-member names in the footer only if required by the official template.

### Presenter Message

> Traditional intrusion detection reports observed malicious activity. Trajectory estimates where that activity is likely to progress next and shows the evidence behind the forecast.

---

## Slide 2: Solution Overview And Prototype

### Slide Headline

## From Static Alerts to Predictive Attack Intelligence

### Solution Summary

Trajectory is an offline software prototype that ingests network-flow records and PCAP-derived packet data, converts them into ordered network states, and forecasts likely attack progression over multiple future time windows. It presents infiltration risk, predicted attack stage, affected assets, confidence, and supporting traffic evidence through an analyst dashboard.

### Problem And Response

| Current limitation | Trajectory response |
|---|---|
| Flow-by-flow detection loses event order | Builds timestamped sequences of network states |
| Alerts explain the present or past | Simulates likely future states over a K-step horizon |
| Weak signals are viewed independently | Correlates reconnaissance, authentication, and internal-access patterns |
| Black-box scores reduce analyst trust | Shows driving features, source events, entities, and uncertainty |

### Features By User Role

#### SOC Analyst

- Upload or select supported CSV flow data and PCAP captures.
- View a time-ordered network-state and risk timeline.
- Inspect the likely next attack stage and affected assets.
- Review the evidence and features supporting each forecast.
- Compare predicted stages with actual replayed events.

#### Incident Responder

- Prioritize hosts, users, servers, or segments at elevated forecast risk.
- Review confidence and insufficient-evidence warnings before acting.
- Use predicted progression as decision support for investigation and containment.
- Export a reproducible forecast and evidence record for review.

#### Security Lead / Evaluator

- Compare the temporal model against a static logistic-regression baseline.
- Review precision, recall, F1, false-positive rate, calibration, and lead time.
- Reproduce a scenario using fixed configuration, seed, and replay data.
- Verify local processing without cloud AI dependencies.

### Project Status

**Current phase: ingestion and temporal-data foundation implemented; baseline modelling is the next milestone.**

Implemented and tested:

- Strict CSV flow ingestion and optional PCAP parsing
- Flow-level and packet-level feature extraction
- Timestamped, overlapping network-state windows
- Future transition targets and contiguous sequence samples
- Scenario-level split manifests that reduce temporal leakage
- Configuration, schema, ingestion, state, and split tests

Do not show a completion percentage unless the team defines and documents how it is calculated.

### Why We Stand Out

- **Predictive rather than retrospective:** estimates likely future attack progression.
- **K-step simulation:** rolls network state forward across multiple future windows.
- **Temporal context:** models event order instead of treating flows independently.
- **Evidence with every forecast:** connects risk to traffic patterns and affected entities.
- **Offline-first:** keeps sensitive telemetry and model inference local.
- **Honest comparison:** evaluates against a static baseline on comparable data.

### Prototype Visuals

Use three connected visual panels:

```text
┌──────────────────────┐  ┌────────────────────────┐  ┌──────────────────────┐
│ 1. DATA WORKSPACE    │  │ 2. FORECAST DASHBOARD │  │ 3. EVIDENCE VIEW     │
│ CSV / PCAP input     │→ │ Risk over K windows    │→ │ Driving features     │
│ Coverage and quality │  │ Stage + confidence     │  │ Assets + source data │
└──────────────────────┘  └────────────────────────┘  └──────────────────────┘
```

Recommended mockup content:

- Panel 1: file input, event count, time range, and feature-coverage indicators
- Panel 2: risk curve with `Current`, `Forecast`, and `Actual Replay` visually separated
- Panel 3: `Server-03`, failed-authentication burst, destination diversity, and confidence

### Example Forecast Card

```text
Current state       Suspicious reconnaissance
Predicted stage     Lateral movement
Forecast horizon    +3 time windows
Likely asset        Server-03
Confidence          0.72
Evidence            Failed-auth burst, new internal connections,
                    increasing destination diversity
```

The example must be labelled **Illustrative Output** until produced by the tested model.

---

## Slide 3: Backend Architecture And Technical Approach

### Slide Headline

## Local, Reproducible, Evidence-First Forecasting Pipeline

### Backend Architecture Diagram

```text
┌──────────────────── INPUT LAYER ────────────────────┐
│ Flow CSV                     PCAP / packet captures │
└───────────────┬──────────────────────┬──────────────┘
                ↓                      ↓
       Flow normalization      Packet feature extraction
                └──────────────┬───────┘
                               ↓
┌──────────────────── DATA LAYER ─────────────────────┐
│ Unified events → timestamped windows → state store │
│ Scenario labels → transition targets → split files │
└──────────────────────────────┬──────────────────────┘
                               ↓
┌──────────────────── MODEL LAYER ────────────────────┐
│ Static baseline             Temporal model          │
│ Logistic Regression        GRU / LSTM              │
│ Current-window score       K-step state rollout    │
└──────────────────────────────┬──────────────────────┘
                               ↓
┌──────────────────── OUTPUT LAYER ───────────────────┐
│ Risk timeline │ Attack stage │ Assets │ Evidence   │
│ Confidence    │ Warnings     │ Replay comparison   │
└──────────────────────────────┬──────────────────────┘
                               ↓
                    Offline Analyst Dashboard
```

Architecture accuracy notes:

- Do not add Kafka, a cloud API gateway, distributed databases, or Docker services unless they are actually implemented.
- The prototype can use local files and model artifacts; production integration is a future deployment path.
- If containerization is completed before submission, show Docker as a packaging boundary around the application rather than inventing microservices.

### Technical Approach Flow

```text
1. INGEST
   Validate flow CSV or parse supported PCAP
        ↓
2. NORMALIZE
   Standardize protocol, TCP flags, timestamps, and feature availability
        ↓
3. WINDOW
   Aggregate ordered events into timestamped network states
        ↓
4. PREPARE
   Create transition targets and scenario-safe train/test splits
        ↓
5. LEARN
   Train static baseline and temporal state-transition model
        ↓
6. SIMULATE
   Roll predicted state forward over K future windows
        ↓
7. EXPLAIN
   Identify driving features, entities, source events, and uncertainty
        ↓
8. DISPLAY
   Present risk timeline, attack stage, likely assets, and evidence
```

### Actor Flow

```text
Security Lead                SOC Analyst                 Incident Responder
Configures scenario          Loads telemetry             Reviews high-risk assets
Runs evaluation       →      Starts replay        →      Validates evidence
Reviews model metrics        Inspects forecast           Chooses response action
```

### AI Components

| Component | Technique | Exact function |
|---|---|---|
| Static baseline | Logistic Regression | Predict the documented target from the current state and establish a fair reference |
| Temporal forecaster | GRU or LSTM | Learn dependencies across ordered network-state windows |
| Future simulation | Recursive K-step rollout | Generate likely future states and a risk trajectory |
| Stage interpretation | Documented rule or classifier mapping | Translate forecast behaviour into a recognised attack-stage label |
| Explanation | Feature attribution plus source-event retrieval | Show influential features and the traffic evidence associated with them |
| Calibration | Probability calibration and reliability analysis | Make confidence values more useful to analysts |

Use `GRU / LSTM` as the proposed choice until model selection is completed. Do not label a planned model as implemented.

### Security And Privacy

- **Local-first processing:** telemetry is processed without an external AI service.
- **Data minimization:** retain only fields required for forecasting and evidence.
- **Identifier protection:** anonymize sensitive endpoint identifiers in demonstrations.
- **Secrets hygiene:** never commit credentials, private captures, or keys.
- **Safe logging:** record metadata and errors without exposing sensitive payloads.
- **Integrity:** record dataset provenance, transformations, versions, and checksums.
- **Human control:** the prototype forecasts and recommends; it does not block traffic automatically.

Avoid claiming full Zero Trust compliance unless access control, identity verification, policy enforcement, and audit mechanisms have been implemented and tested.

### Offline And Input Fallback Logic

Replace generic internet/mesh fallback with the actual operating model:

```text
Telemetry available?
       │
       ├─ Flow CSV available ──→ Flow features + explicit packet-coverage warning
       │
       ├─ PCAP available ──────→ Flow and supported packet-derived features
       │
       └─ Required data absent → Validation error; no fabricated prediction

All paths run locally without cloud inference.
```

### Technology Footer

`Python` · `Pandas` · `NumPy` · `Scikit-learn` · `PyTorch` · `Scapy/PyShark` · `Streamlit/Flask` · `Plotly` · `NetworkX` · `MITRE ATT&CK`

Only highlight libraries included in the demonstrated build.

---

## Slide 4: Feasibility, Viability And Challenges

### Slide Headline

## Feasible with Open Data, Local Compute, and Controlled Deployment

### Four-Part Feasibility Grid

| Technical | Operational |
|---|---|
| Public flow and PCAP datasets are available | Runs beside existing IDS, SIEM, firewall, or EDR workflows |
| Open-source parsers and ML frameworks support the MVP | Analyst remains responsible for response decisions |
| GRU/LSTM models are practical on development hardware | Deterministic replay makes evaluation and demos repeatable |
| Scenario-safe splits and baseline comparison are defined | Local processing supports sensitive environments |

| Economic | Regulatory And Privacy |
|---|---|
| Open-source stack reduces prototype licensing cost | Demo data can be synthetic, public, or anonymized |
| Software-only MVP requires no custom hardware | Dataset licences and access restrictions are recorded |
| Can augment rather than replace existing security tools | Sensitive captures and model artifacts remain local |
| Phased adoption allows pilot-first validation | Human approval prevents autonomous enforcement risk |

### Market Viability Chart

Use one externally sourced cybersecurity-market series and cite it directly below the chart.

```text
Market size
    │                              █
    │                        █     █
    │                  █     █     █
    │            █     █     █     █
    │      █     █     █     █     █
    └──────────────────────────────────
        Base  Y+1   Y+2   Y+3   Y+4

        CAGR: [ADD VERIFIED VALUE]%
        Source: [ADD REPORT, PUBLISHER, YEAR, URL]
```

Rules for the chart:

- Choose a market directly related to network security, intrusion detection/prevention, or security analytics.
- Do not combine figures from reports with different definitions.
- State whether values are global, Indian, product-only, or services-inclusive.
- If the full source is paywalled, cite the accessible publisher summary containing the figure.

### Challenges And Technical Responses

| Anticipated challenge | Technical response |
|---|---|
| Rare and imbalanced attacks | Class weighting, per-class metrics, and precision-recall analysis |
| Temporal leakage | Scenario-, campaign-, source-, or time-held-out evaluation |
| Dataset shift | Secondary-dataset testing and environment-specific recalibration |
| Missing packet features | Feature-coverage report and explicit reduced-context warning |
| Recursive forecast drift | Short K-step horizon, calibration, and uncertainty display |
| Ambiguous stage labels | Documented mapping rules and an insufficient-evidence state |
| False-positive fatigue | Baseline comparison, threshold tuning, and false-positive-rate reporting |
| Black-box predictions | Feature attribution, source-event evidence, and affected-asset context |
| Sensitive telemetry | Local processing, anonymization, and restricted artifacts |
| Enterprise integration | File-based MVP first; documented adapters and APIs as a future phase |

### Practical MVP Boundary

**Included:** offline CSV/PCAP analysis, temporal states, static baseline, GRU/LSTM forecast, K-step simulation, stage mapping, explanations, and replay.

**Not claimed:** live packet interception, production SOC integration, autonomous blocking, guaranteed zero-day detection, or perfect attack prediction.

### Viability Statement

> Trajectory is feasible as an offline prototype using public datasets and open-source tools. Production use requires environment-specific validation, integration, calibration, access control, and security review.

---

## Slide 5: Impacts, Benefits And Stakeholder Scenario

### Slide Headline

## Earlier Evidence-Backed Decisions Can Reduce Attack Impact

### Impacts And Benefits

#### Economic

- Focuses limited analyst time on likely attack paths and affected assets.
- Can reduce manual correlation effort across fragmented alerts.
- Supports earlier intervention that may reduce downtime and response cost.
- Adds predictive capability without replacing an entire security stack.

#### Social

- Supports the resilience of public services and critical digital infrastructure.
- Helps defenders investigate developing incidents with clearer context.
- Keeps human analysts responsible for consequential response decisions.
- Encourages explainable and accountable use of AI in cybersecurity.

#### Environmental

- Runs locally on ordinary development hardware for the prototype.
- Reuses existing telemetry and security infrastructure.
- Avoids mandatory cloud transfer and continuous cloud inference.
- Software-only deployment avoids custom device manufacturing.

#### Operational

- Forecasts likely progression before the next stage is fully observable.
- Connects stage, asset, probability, time horizon, and evidence.
- Provides repeatable replay for training, evaluation, and audit.
- Works as a predictive layer alongside existing detection controls.

### Sample Stakeholder Scenario

```text
NETWORK TELEMETRY
Normal enterprise activity establishes a baseline
        ↓
WORKSTATION-17
Contacts many new destinations; port and timing patterns become abnormal
        ↓
TRAJECTORY
Correlates reconnaissance with a burst of failed authentication activity
        ↓
SOC ANALYST
Receives an early forecast of likely lateral movement toward Server-03
        ↓
INCIDENT RESPONDER
Reviews evidence, validates the asset, and chooses an appropriate action
        ↓
SECURITY LEAD
Audits forecast, confidence, evidence, actual outcome, and response timeline
```

Prototype success criteria for this scenario:

- The forecast appears before the target-stage event becomes observable.
- The evidence names relevant traffic patterns and entities.
- Forecast and actual replay are visually distinct.
- The same configuration reproduces the same replay sequence.

### Sustainable Development Goals

Use official icons only if permitted by the SIH template and UN branding guidance.

| SDG | Connection to Trajectory |
|---|---|
| **SDG 9: Industry, Innovation and Infrastructure** | Strengthens the resilience of digital and critical infrastructure through predictive security analytics |
| **SDG 16: Peace, Justice and Strong Institutions** | Supports safer digital public systems and accountable, evidence-backed security operations |

Do not add SDGs without a direct and defensible project connection.

### Quantitative Target Impact

Use a measured evaluation result or a clearly labelled target. Recommended calculation:

```text
Forecast lead time
= Timestamp when target attack stage becomes observable
− Timestamp when Trajectory first crosses the validated warning threshold

Analyst time saved per incident
= Current mean investigation time
− Mean investigation time with the Trajectory evidence panel

Annual analyst hours potentially recovered
= Valid investigated incidents per year × measured time saved per incident
```

Slide-ready result block after testing:

```text
[X] min median forecast lead time
[Y]% reduction in investigation time during controlled user testing
[Z] analyst-hours potentially recovered per year

Evaluation basis: [DATASET / NUMBER OF SCENARIOS / TEST METHOD]
```

Do not convert model accuracy directly into financial savings without an explained operational assumption.

---

## Slide 6: Research, Market Sizing And Business Model

### Slide Headline

## Research-Backed, Scalable from Offline Pilot to Enterprise Integration

### Categorized References

#### Official And Domain References

- SIH 2026 Problem Statements: `https://sih.gov.in/sih2026PS`
- MITRE ATT&CK: `https://attack.mitre.org/`
- CAPEC: `https://capec.mitre.org/`
- NIST National Vulnerability Database: `https://nvd.nist.gov/`
- NCIIPC: `https://nciipc.gov.in/`

#### Dataset References

- CIC-IDS2017/2018: `[ADD VERIFIED DATASET URL]`
- UNSW-NB15: `[ADD VERIFIED DATASET URL]`
- CTU-13: `[ADD VERIFIED DATASET URL]`
- CICIoT2023: `[ADD VERIFIED DATASET URL]`
- LANL authentication data: `[ADD VERIFIED DATASET URL]`

Use only datasets whose source, licence, access conditions, checksums, and transformations are documented.

#### AI/ML Research

- Temporal sequence modelling for network behaviour
- GRU/LSTM-based time-series forecasting
- Recursive multi-step forecasting and uncertainty
- Probability calibration and reliability analysis
- Feature attribution and explainable AI
- Scenario-held-out evaluation for intrusion detection

Add two to four specific peer-reviewed papers actually used by the implementation:

```text
[AUTHOR, TITLE, VENUE, YEAR, DOI/URL]
```

#### Software References

- PyTorch: `https://pytorch.org/`
- Scikit-learn: `https://scikit-learn.org/`
- Scapy: `https://scapy.net/`
- NetworkX: `https://networkx.org/`
- Plotly: `https://plotly.com/python/`

### Market Sizing Framework

Use a bottom-up calculation rather than unsupported global-market percentages.

| Measure | Definition | Calculation template |
|---|---|---|
| TAM | All target organizations that operate network-security teams in the chosen geography | `[Eligible organizations] × [Annual licence value]` |
| SAM | Organizations reachable with the initial offline product and supported integrations | `[TAM organizations in priority sectors] × [Annual licence value]` |
| SOM | Realistic customers obtainable during the first 3 years | `[SAM organizations] × [Documented adoption rate] × [Annual value]` |

Slide-ready placeholder:

```text
TAM = [N1 organizations] × ₹[A] annual value = ₹[TAM]
SAM = [N2 priority organizations] × ₹[A]       = ₹[SAM]
SOM = [N3 three-year customers] × ₹[A]        = ₹[SOM]
```

Required assumptions:

- Target geography and sectors
- Source for organization count
- Product scope included in annual value
- Adoption period and obtainable-customer rationale
- Whether taxes, integration, support, and hardware are included

### Revenue Model

Trajectory is a software-first solution; custom hardware is not required for the MVP.

| Revenue component | Unit | Proposed pricing basis |
|---|---|---|
| Offline platform licence | Per organization or monitored environment/year | `[ADD VALIDATED PRICE]` |
| Deployment and integration | One-time per environment | Based on supported data sources and SIEM integration effort |
| Model calibration | Per environment or major telemetry change | Based on data preparation, validation, and threshold tuning |
| Support and updates | Annual service | Percentage of licence or defined support tier |
| Training and simulation | Per analyst cohort | Scenario setup, replay exercises, and reporting |
| Hardware | Not required for MVP | Customer-provided workstation/server; list minimum specifications |

### First-Year Revenue Template

```text
Platform licences     [L customers] × ₹[licence]     = ₹[R1]
Deployments           [D sites]     × ₹[deployment]  = ₹[R2]
Support contracts     [S contracts] × ₹[support]     = ₹[R3]
Training cohorts      [T cohorts]   × ₹[training]    = ₹[R4]
                                                      ─────────
First-year revenue estimate                           = ₹[TOTAL]
```

Label the result as a **business estimate**, not current revenue.

### Proof Documents And Clickable Links

- Source repository: `[ADD PUBLIC OR JUDGE-ACCESSIBLE GITHUB URL]`
- Architecture: link to `ARCHITECTURE.md` or hosted documentation
- Implementation status: link to `IMPLEMENTATION_STATUS.md`
- Evaluation report: `[ADD LINK AFTER BENCHMARKS ARE COMPLETE]`
- Demo video: `[ADD FINAL VIDEO LINK]`
- Consolidated research: `[ADD DRIVE OR REPOSITORY FOLDER LINK]`
- Reproducibility instructions: link to `README.md` and environment lock file

Before PDF export, verify that every hyperlink remains clickable and that judges have permission to open it.

### Closing Line

> **Trajectory adds a predictive intelligence layer to existing cyber defence: forecasting what may happen next, where it may happen, and why the analyst should pay attention.**

---

## Final Slide Map

| Slide | Primary question answered | Main visual |
|---|---|---|
| 1. Title And Registration | Who are we and which problem are we solving? | Telemetry-to-forecast hero flow |
| 2. Solution And Prototype | What does Trajectory do and why is it different? | Three-panel prototype mockup |
| 3. Architecture And Approach | How does the system work safely and technically? | Layered architecture plus process flow |
| 4. Feasibility And Viability | Can it be built, adopted, and trusted? | Four-part grid plus challenge/response table |
| 5. Impact And Scenario | Who benefits and how will impact be measured? | Stakeholder journey plus SDGs and metrics |
| 6. Research And Business | What supports the idea and how can it scale? | References, TAM/SAM/SOM, and revenue model |

## Claims Checklist

### Safe Language

- Forecast or estimate
- Likely progression
- Predicted attack stage
- Supporting evidence
- Model confidence
- Scenario-held-out evaluation
- Offline prototype
- Analyst decision support
- Potential impact or measured impact

### Avoid

- Guaranteed prevention
- Perfect prediction or 100% accuracy
- Fully autonomous defence
- Zero Trust compliant without implementation evidence
- Zero-day detection guarantee
- Production-ready before enterprise validation
- Replaces SOC analysts or existing security tools
- Causal proof from feature attribution
- Unsupported market share, savings, or revenue

## Pre-Submission Checklist

- Replace Team ID, Team Name, institute, and all other registration placeholders.
- Confirm event name, problem title, category, theme, and organization on the official portal.
- Replace illustrative prototype panels with current screenshots.
- Update project status from `IMPLEMENTATION_STATUS.md` immediately before submission.
- Mark planned model components clearly until implementation and testing are complete.
- Insert measured model metrics and forecast lead time from the final evaluation report.
- Add a verified market source and explain every TAM/SAM/SOM assumption.
- Replace all repository, research, evaluation, and video placeholders with accessible links.
- Test links after exporting the official template to PDF.
- Ensure every chart has a readable source and every number has a calculation basis.
- Keep font sizes readable and avoid paragraphs that require zooming.
- Ensure the six slides tell one consistent story: **state → trajectory → forecast → evidence → earlier decision**.
