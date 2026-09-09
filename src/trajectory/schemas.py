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
    event_type: Literal["flow", "packet", "authentication", "other"]
    features: dict[str, float] = Field(default_factory=dict)
    source_format: Literal["csv", "pcap", "replay", "other"]
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
