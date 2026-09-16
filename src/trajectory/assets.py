# SPDX-License-Identifier: Apache-2.0
"""Asset criticality registry and risk fusion.

Risk is made explicit rather than magical: every assessment carries the
formula that produced it, and the fusion weights are the single source of
truth for both scoring and dashboard display.
"""

from __future__ import annotations

import json
from pathlib import Path

from trajectory.schemas import AssetRecord, RiskAssessment

# Criticality weight per level, used by the fusion formula.
CRITICALITY_WEIGHT = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}
SEVERITY_WEIGHT = {"info": 0.0, "low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}
EVIDENCE_WEIGHT = 1.0  # placeholder until per-finding evidence confidence is fused

RISK_FORMULA = (
    "0.5*probability + 0.3*asset_criticality + 0.2*severity (weights fixed in trajectory.assets)"
)


def load_asset_registry(path: Path) -> dict[str, AssetRecord]:
    """Load the registry from JSON: {"server-03": {role, owner, ...}, ...}."""
    data = json.loads(path.read_text(encoding="utf-8"))
    records = [
        AssetRecord.model_validate({"asset_id": asset_id, **fields})
        for asset_id, fields in data.items()
    ]
    return {record.asset_id: record for record in records}


def default_asset_registry() -> dict[str, AssetRecord]:
    """Registry matching the synthetic/lab topology (servers, not workstations)."""
    entries = {
        "auth-service": {
            "role": "Authentication service",
            "owner": "Security",
            "criticality": "critical",
            "data_sensitivity": "restricted",
            "network_zone": "internal",
        },
        "server-03": {
            "role": "Production database",
            "owner": "Finance",
            "criticality": "critical",
            "data_sensitivity": "restricted",
            "network_zone": "internal",
        },
        "file-server": {
            "role": "File services",
            "owner": "IT",
            "criticality": "high",
            "data_sensitivity": "internal",
            "network_zone": "internal",
        },
        "web-proxy": {
            "role": "Egress proxy",
            "owner": "IT",
            "criticality": "medium",
            "data_sensitivity": "internal",
            "network_zone": "dmz",
        },
    }
    records = [AssetRecord.model_validate({"asset_id": k, **v}) for k, v in entries.items()]
    return {record.asset_id: record for record in records}


def risk_level(score: float) -> str:
    if score >= 0.80:
        return "critical"
    if score >= 0.60:
        return "high"
    if score >= 0.35:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def fuse_risk(
    probability: float,
    severity: str,
    affected_assets: list[str],
    registry: dict[str, AssetRecord] | None,
) -> RiskAssessment:
    """Fuse finding probability, asset criticality, and severity into risk.

    The severity contribution uses the maximum severity across affected
    assets' exposure; with no registry, criticality contributes a neutral 0.5
    and the formula says so.
    """
    registered = [a for a in affected_assets if a in registry] if registry else []
    worst = (
        max(CRITICALITY_WEIGHT.get(registry[a].criticality, 0.5) for a in registered)
        if registered
        else 0.5
    )
    score = 0.5 * probability + 0.3 * worst + 0.2 * SEVERITY_WEIGHT.get(severity, 0.0)
    formula = RISK_FORMULA
    if not (registry and registered):
        formula += " [no registry match — neutral criticality]"
    return RiskAssessment(
        score=round(score, 3),
        level=risk_level(score),
        formula=formula,
    )
