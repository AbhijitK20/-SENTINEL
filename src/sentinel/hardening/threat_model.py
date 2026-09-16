# SPDX-License-Identifier: Apache-2.0
"""Threat model for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class STRIDECategory(Enum):
    """STRIDE threat categories."""

    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


@dataclass
class Threat:
    """Threat model entry."""

    component: str
    category: STRIDECategory
    description: str
    mitigation: str
    residual_risk: str


# STRIDE threats per component
THREATS: list[Threat] = [
    Threat(
        component="API Gateway",
        category=STRIDECategory.SPOOFING,
        description="Attacker impersonates a legitimate user",
        mitigation="JWT validation, API key authentication, rate limiting",
        residual_risk="Low",
    ),
    Threat(
        component="API Gateway",
        category=STRIDECategory.TAMPERING,
        description="Attacker modifies request data in transit",
        mitigation="TLS 1.3, input validation with Pydantic, CSRF protection",
        residual_risk="Low",
    ),
    Threat(
        component="API Gateway",
        category=STRIDECategory.REPUDIATION,
        description="User denies performing an action",
        mitigation="Audit logging with immutable hash chain",
        residual_risk="Low",
    ),
    Threat(
        component="API Gateway",
        category=STRIDECategory.INFORMATION_DISCLOSURE,
        description="Sensitive data exposed in responses",
        mitigation="Output encoding, PII redaction, minimal error messages",
        residual_risk="Low",
    ),
    Threat(
        component="API Gateway",
        category=STRIDECategory.DENIAL_OF_SERVICE,
        description="Attacker overwhelms the system",
        mitigation="Rate limiting, request size limits, timeout configuration",
        residual_risk="Medium",
    ),
    Threat(
        component="API Gateway",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        description="Attacker gains unauthorized access",
        mitigation="RBAC/ABAC, tenant isolation, principle of least privilege",
        residual_risk="Low",
    ),
    Threat(
        component="Inference Worker",
        category=STRIDECategory.SPOOFING,
        description="Malicious input crafted to evade detection",
        mitigation="Input validation, adversarial training, model robustness testing",
        residual_risk="Medium",
    ),
    Threat(
        component="Inference Worker",
        category=STRIDECategory.TAMPERING,
        description="Model weights or artifacts modified",
        mitigation="Artifact checksums, signed releases, secure model loading",
        residual_risk="Low",
    ),
    Threat(
        component="Database",
        category=STRIDECategory.INFORMATION_DISCLOSURE,
        description="Cross-tenant data leakage",
        mitigation="RLS policies, tenant isolation testing, parameterized queries",
        residual_risk="Low",
    ),
    Threat(
        component="Database",
        category=STRIDECategory.TAMPERING,
        description="Unauthorized data modification",
        mitigation="Audit logging, immutable records, access controls",
        residual_risk="Low",
    ),
    Threat(
        component="Event Bus",
        category=STRIDECategory.DENIAL_OF_SERVICE,
        description="Message queue overflow",
        mitigation="Backpressure, bounded queues, load shedding",
        residual_risk="Medium",
    ),
    Threat(
        component="File Upload",
        category=STRIDECategory.TAMPERING,
        description="Malicious PCAP/CSV uploaded",
        mitigation="Sandboxed parsing, resource limits, type validation",
        residual_risk="Low",
    ),
]


def get_threats_by_component(component: str) -> list[Threat]:
    """Get threats for a specific component."""
    return [t for t in THREATS if t.component == component]


def get_threats_by_category(category: STRIDECategory) -> list[Threat]:
    """Get threats for a specific category."""
    return [t for t in THREATS if t.category == category]


def get_all_threats() -> list[Threat]:
    """Get all threats."""
    return THREATS
