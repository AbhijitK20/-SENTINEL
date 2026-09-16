# SPDX-License-Identifier: Apache-2.0
"""Stable contracts shared by ingestion, modelling, and the UI."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class UnifiedEvent(BaseModel):
    """A normalized event from CSV, PCAP, or another telemetry adapter."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    source_entity: str = Field(min_length=1)
    destination_entity: str = Field(min_length=1)
    event_type: Literal["flow", "packet", "authentication", "dns_query", "auth_event", "other"]
    features: dict[str, float] = Field(default_factory=dict)
    source_format: Literal[
        "csv", "pcap", "replay", "dns_log_stub", "auth_log_stub", "syslog", "other"
    ]
    provenance: str = Field(min_length=1)


class NetworkState(BaseModel):
    """Aggregated network behaviour for one time window."""

    model_config = ConfigDict(extra="forbid")

    window_start: datetime
    window_end: datetime
    features: dict[str, float] = Field(default_factory=dict)
    entities: list[str] = Field(default_factory=list)
    edge_summary: list[dict[str, str | float]] = Field(default_factory=list)
    coverage: dict[str, bool] = Field(default_factory=dict)
    source_ids: list[str] = Field(default_factory=list)


class StateLabel(BaseModel):
    """Observed or derived label associated with one network state."""

    model_config = ConfigDict(extra="forbid")

    state_key: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    infiltration: bool
    attack_stage: str = Field(min_length=1)
    label_source: Literal["dataset", "derived", "replay", "unknown"]


class TransitionTarget(BaseModel):
    """Future state target for transition-model training."""

    model_config = ConfigDict(extra="forbid")

    source_state_key: str = Field(min_length=1)
    target_state_key: str = Field(min_length=1)
    horizon: int = Field(ge=1)
    scenario_id: str = Field(min_length=1)
    target_features: dict[str, float] = Field(default_factory=dict)
    target_infiltration: bool
    target_stage: str = Field(min_length=1)


class SequenceSample(BaseModel):
    """Leakage-safe sequence sample used by baseline and temporal models."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    input_state_keys: list[str] = Field(min_length=1)
    target: TransitionTarget


class SplitManifest(BaseModel):
    """Scenario-level split assignment used for reproducible evaluation."""

    model_config = ConfigDict(extra="forbid")

    seed: int = Field(ge=0)
    train_scenarios: list[str]
    validation_scenarios: list[str]
    test_scenarios: list[str]


SPLIT_NAMES = ("train", "validation", "test")


def split_assignment(manifest: SplitManifest) -> dict[str, str]:
    """Map each scenario to its split name."""
    assignment: dict[str, str] = {}
    for name in SPLIT_NAMES:
        for scenario in getattr(manifest, f"{name}_scenarios"):
            assignment[scenario] = name
    return assignment


class ProbabilityPoint(BaseModel):
    """One point in a future infiltration probability timeline."""

    window: int = Field(ge=1)
    infiltration_probability: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)


class PredictedStage(BaseModel):
    """Predicted attack stage with calibrated or explicitly raw confidence later."""

    name: str = Field(min_length=1)
    probability: float = Field(ge=0, le=1)
    confidence: Literal["low", "medium", "high", "unknown"]


class StageEvidence(BaseModel):
    """One documented, observable feature fact supporting a stage hypothesis.

    Evidence is an association observed in the current window; it is never
    presented as proof of an attack technique.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    observed_value: float | None = None
    direction: Literal["increasing", "decreasing", "flat", "unknown"] = "unknown"
    confidence: float = Field(ge=0.0, le=1.0)


class StageMapping(BaseModel):
    """MITRE-oriented stage mapping with an explicit insufficient-evidence state."""

    model_config = ConfigDict(extra="forbid")

    stage: str = Field(min_length=1)
    probability: float = Field(ge=0.0, le=1.0)
    confidence: Literal["low", "medium", "high", "unknown"]
    mitre_reference: str | None = None
    mapping_version: str = Field(min_length=1)
    evidence: list[StageEvidence] = Field(default_factory=list)
    rationale: str = Field(min_length=1)


class LeadTimeEstimate(BaseModel):
    """How early the timeline crosses the decision threshold.

    ``lead_windows`` is ``None`` when the threshold is never crossed within
    the forecast horizon; the absence is explicit, never silently zero.
    """

    model_config = ConfigDict(extra="forbid")

    lead_windows: int | None = Field(default=None, ge=1)
    horizon_windows: int = Field(gt=0)
    threshold: float = Field(gt=0.0, lt=1.0)
    definition: str = Field(min_length=1)


class DrivingFeature(BaseModel):
    """Feature evidence associated with a forecast."""

    name: str = Field(min_length=1)
    contribution: float
    direction: Literal["increasing", "decreasing", "mixed", "unknown"]


class AttackFinding(BaseModel):
    """One attack-type detector's normalized output for a single window.

    Every detector emits this contract regardless of its internal features, so
    the fusion layer and dashboard need no detector-specific code. Findings are
    associations observed in telemetry, never proof of a technique.
    """

    model_config = ConfigDict(extra="forbid")

    attack_type: Literal[
        "ddos",
        "reconnaissance",
        "credential_abuse",
        "lateral_movement",
        "command_and_control",
        "exfiltration",
        "insider_threat",
        "phishing",
        "malware_activity",
    ]
    probability: float = Field(ge=0.0, le=1.0)
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    is_alert: bool = False
    window_start: datetime | None = None
    window_end: datetime | None = None
    mitre_technique: str | None = None
    affected_assets: list[str] = Field(default_factory=list)
    evidence: list[StageEvidence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    model_version: str = Field(min_length=1)


class AssetRecord(BaseModel):
    """Static criticality metadata for one asset in the registry."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    criticality: Literal["low", "medium", "high", "critical"]
    data_sensitivity: str = Field(min_length=1)
    network_zone: str = Field(min_length=1)


class RiskAssessment(BaseModel):
    """Fused risk for a finding or incident, with the formula kept explicit."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0)
    level: Literal["info", "low", "medium", "high", "critical"]
    formula: str = Field(min_length=1)


class Incident(BaseModel):
    """Correlated chain of findings presented as one analyst-facing case.

    ``progression`` lists attack stages in attack order (e.g. Reconnaissance →
    Credential Abuse → Lateral Movement); ``recommended_actions`` are analyst-
    approved suggestions only — the platform never auto-executes them.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    risk: RiskAssessment
    progression: list[str] = Field(min_length=1)
    finding_attack_types: list[str] = Field(min_length=1)
    affected_assets: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    status: Literal["open", "investigating", "contained", "closed", "false_positive"] = "open"
    recommended_actions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AnalystFeedback(BaseModel):
    """Analyst verdict on a finding or incident.

    Feedback is stored append-only for threshold recalibration and rule
    improvement review. It is never used to automatically retrain models.
    """

    model_config = ConfigDict(extra="forbid")

    subject_id: str = Field(min_length=1)
    verdict: Literal[
        "true_positive",
        "false_positive",
        "wrong_attack_type",
        "late_alert",
        "insufficient_evidence",
        "useful_alert",
    ]
    analyst: str = Field(min_length=1)
    recorded_at: datetime
    comment: str = ""


class SignedFeedback(BaseModel):
    """Analyst feedback with an HMAC signature over its content (Phase 6).

    The signing key is shared secret between the platform and the analyst
    tooling; verification catches post-hoc tampering of stored feedback.
    Full asymmetric signatures with a PKI are future work.
    """

    model_config = ConfigDict(extra="forbid")

    feedback: AnalystFeedback
    signature: str = Field(min_length=1)
    key_version: str = Field(min_length=1)


class Forecast(BaseModel):
    """Serializable inference output shown to an analyst."""

    model_config = ConfigDict(extra="forbid")

    input_window_start: datetime
    input_window_end: datetime
    horizon_windows: int = Field(gt=0)
    model_version: str = Field(min_length=1)
    probability_timeline: list[ProbabilityPoint]
    predicted_stage: PredictedStage
    stage_mapping: StageMapping | None = None
    lead_time: LeadTimeEstimate | None = None
    affected_entities: list[str] = Field(default_factory=list)
    driving_features: list[DrivingFeature] = Field(default_factory=list)
    supporting_events: list[str] = Field(default_factory=list)
    coverage: dict[str, bool] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
