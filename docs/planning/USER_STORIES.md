# User Stories

## Story Format

Each story has a user outcome, acceptance criteria, and traceability references.

## Stories

### US-001: Ingest Flow Records

As a SOC analyst, I want to load a supported flow CSV so that I can analyse network behaviour offline.

Acceptance criteria:

- Given a valid supported CSV, when ingestion runs, then normalized events are produced.
- Invalid or missing required columns produce an actionable error.

Links: EPIC-02, F-001, REQ-PS-004.

### US-002: Ingest PCAP

As a SOC analyst, I want to load a PCAP so that packet-level behaviour is available to the forecast.

Acceptance criteria:

- Given a readable PCAP, packet and derived flow features are produced.
- Parser statistics and unsupported-feature warnings are visible.

Links: EPIC-02, F-002, REQ-PS-005.

### US-003: View Network State

As an analyst, I want to see timestamped network states so that I can understand what the model is observing.

Acceptance criteria:

- A state has a time window, feature values, entities, and data-coverage metadata.
- Observed data is visually distinct from prediction.

Links: EPIC-04, F-006, F-007, REQ-PS-001.

### US-004: Forecast Future Progression

As an analyst, I want a K-window forecast so that I can investigate likely next attack behaviour.

Acceptance criteria:

- A forecast contains probabilities for each future window.
- The rollout starts from the selected observed state.
- Horizon and model version are shown.

Links: EPIC-06, EPIC-07, F-010, F-011, REQ-PS-003, REQ-PS-006, REQ-PS-007.

### US-005: See Attack Stage

As an analyst, I want a likely attack stage so that I can prioritize investigation.

Acceptance criteria:

- Stage output uses the documented stage vocabulary.
- Unknown or insufficient evidence is supported.

Links: EPIC-08, F-013, F-014, REQ-PS-008.

### US-006: Understand The Evidence

As an analyst, I want the driving features and events so that I can assess forecast credibility.

Acceptance criteria:

- Every forecast includes ranked evidence or an explicit unavailable explanation.
- Evidence identifies observed features and relevant entities.

Links: EPIC-09, F-015, REQ-PS-009.

### US-007: Compare Models

As an evaluator, I want a logistic-regression comparison so that temporal value is measurable.

Acceptance criteria:

- Both models use documented comparable inputs and splits.
- Precision, recall, F1, and false-positive rate are reported.

Links: EPIC-05, EPIC-10, F-009, F-019, REQ-PS-012.

### US-008: Replay A Scenario

As a judge, I want a deterministic attack replay so that I can see whether the forecast precedes the next stage.

Acceptance criteria:

- Replay produces the same sequence under the same configuration.
- Actual next state can be compared with the prior forecast.

Links: EPIC-11, F-018, F-020, REQ-PS-014.

### US-009: Run Without Cloud Services

As a CII operator, I want the demonstration to run locally so that sensitive telemetry does not require external APIs.

Acceptance criteria:

- Clean local setup works without cloud AI credentials.
- Offline test blocks network-dependent runtime calls.

Links: EPIC-11, F-020, REQ-PS-011.
