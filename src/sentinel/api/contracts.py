# SPDX-License-Identifier: Apache-2.0
"""API contracts for SENTINEL."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PaginationParams(BaseModel):
    """Pagination parameters for cursor-based pagination."""

    cursor: str | None = None
    limit: int = Field(default=20, ge=1, le=100)


class PaginatedResponse(BaseModel):
    """Paginated response with cursor."""

    data: list[Any]
    next_cursor: str | None = None
    has_more: bool = False


class ErrorDetail(BaseModel):
    """RFC 9457 Problem Details error."""

    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: str = ""
    trace_id: str = ""
    errors: list[dict[str, Any]] = Field(default_factory=list)


class AuthTokenRequest(BaseModel):
    """Authentication token request."""

    grant_type: str = "password"
    username: str
    password: str
    client_id: str = ""


class AuthTokenResponse(BaseModel):
    """Authentication token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600
    refresh_token: str = ""


class DataSourceCreate(BaseModel):
    """Create data source request."""

    name: str
    type: str
    config: dict[str, Any] = Field(default_factory=dict)


class DataSourceResponse(BaseModel):
    """Data source response."""

    id: str
    name: str
    type: str
    config: dict[str, Any] = Field(default_factory=dict)
    status: str = "active"
    created_at: str = ""


class EventBatchRequest(BaseModel):
    """Batch event ingestion request."""

    events: list[dict[str, Any]]
    idempotency_key: str = ""


class EventBatchResponse(BaseModel):
    """Batch event ingestion response."""

    accepted: int
    rejected: int
    errors: list[dict[str, Any]] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    """Analysis request for PCAP/CSV upload."""

    file_type: str
    options: dict[str, Any] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    """Analysis response."""

    job_id: str
    status: str = "pending"
    created_at: str = ""


class AlertResponse(BaseModel):
    """Alert response."""

    id: str
    attack_type: str
    probability: float
    severity: str
    confidence: str
    is_alert: bool
    mitre_technique: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = ""


class CaseCreate(BaseModel):
    """Create case request."""

    title: str
    description: str = ""
    priority: str = "medium"
    assignee_id: str = ""


class CaseResponse(BaseModel):
    """Case response."""

    id: str
    title: str
    description: str = ""
    status: str = "open"
    priority: str = "medium"
    assignee_id: str = ""
    created_at: str = ""
    updated_at: str = ""


class ForecastResponse(BaseModel):
    """Forecast response."""

    id: str
    host_id: str
    risk_score: float
    stage: str = ""
    stage_probs: dict[str, float] = Field(default_factory=dict)
    window_start: str = ""
    window_end: str = ""


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str = ""
    database: str = "ok"
    event_bus: str = "ok"


class ForecastRequest(BaseModel):
    """Forecast request."""

    entity_id: str
    horizon: int = Field(default=5, ge=1, le=20)
    include_explanation: bool = True
    explanation_method: str = "shap-exact-linear"


class ModelResponse(BaseModel):
    """Model registry response."""

    version: str
    kind: str
    status: str
    metrics: dict[str, float] = Field(default_factory=dict)
    created_at: str = ""


class DriftResponse(BaseModel):
    """Drift evaluation response."""

    feature: str
    psi: float
    threshold: float
    status: str  # "ok" | "warning" | "critical"
    training_mean: float = 0.0
    current_mean: float = 0.0


class ComplianceResponse(BaseModel):
    """Compliance mapping response."""

    framework: str
    controls: list[dict[str, str]] = Field(default_factory=list)
    coverage: float = 0.0
    gaps: list[str] = Field(default_factory=list)


class CaseTransitionRequest(BaseModel):
    """Case transition request."""

    target_status: str
    comment: str = ""


class FeedbackRequest(BaseModel):
    """Analyst feedback request."""

    finding_id: str
    verdict: str  # "true_positive" | "false_positive" | "inconclusive"
    signature: str = ""
