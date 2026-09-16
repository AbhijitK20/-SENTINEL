# SPDX-License-Identifier: Apache-2.0
"""Compliance reporting (roadmap Phase 10): control mapping from real state.

Each control cites the module that implements it, so the report is auditable
against the codebase. Controls with no implementation are emitted as "gap"
— the report never claims coverage that does not exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Framework = Literal["NIST_CSF", "ISO_27001", "SOC2"]

IMPLEMENTED_CONTROLS: list[dict[str, str]] = [
    {
        "control": "PR.PS-6 / A.12.4.1 / CC7.2",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "Audit logging of API access (including denials)",
        "implemented_by": "sentinel.auth.AuditLog",
    },
    {
        "control": "PR.AC-1 / A.9.2.3 / CC6.1",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "API-key identity management with RBAC (4 roles)",
        "implemented_by": "sentinel.auth",
    },
    {
        "control": "PR.DS-2 / A.10.1.1 / CC6.7",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "Cryptographic protection of records in transit chain (SHA-256 hash chain)",
        "implemented_by": "sentinel.ledger",
    },
    {
        "control": "DE.CM-1 / A.12.4.3 / CC7.2",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "Network monitoring with attack-type detection and incident correlation",
        "implemented_by": "sentinel.detectors, sentinel.correlation",
    },
    {
        "control": "RS.MI-1 / A.16.1.5 / CC7.5",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "Incident containment via analyst-approved case lifecycle with SLA",
        "implemented_by": "sentinel.cases",
    },
    {
        "control": "PR.DS-1 / A.8.2.3 / CC6.1",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "Model artifacts integrity via SHA-256 checksums at load",
        "implemented_by": "sentinel.predict.load_artifacts",
    },
]

GAPPED_CONTROLS: list[dict[str, str]] = [
    {
        "control": "PR.AC-7 / A.9.4.2 / CC6.1",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "MFA for user access — requires an identity provider",
        "gap_reason": "SSO/OIDC/MFA not implemented; needs real IdP",
    },
    {
        "control": "PR.DS-5 / A.18.1.4 / CC6.7",
        "framework": "NIST_CSF, ISO_27001, SOC2",
        "description": "Encryption at rest for stored records",
        "gap_reason": "JSONL stores are plaintext; at-rest encryption not implemented",
    },
]


class ControlStatus(BaseModel):
    """One control row in the compliance report."""

    model_config = ConfigDict(extra="forbid")

    control: str = Field(min_length=1)
    framework: str = Field(min_length=1)
    description: str = Field(min_length=1)
    status: Literal["implemented", "gap"]
    evidence: str = ""


class ComplianceReport(BaseModel):
    """Aggregated compliance posture at one point in time."""

    model_config = ConfigDict(extra="forbid")

    generated_at: str = Field(min_length=1)
    implemented: list[ControlStatus]
    gaps: list[ControlStatus]
    coverage: float = Field(ge=0.0, le=1.0)

    def to_markdown(self) -> str:
        lines = [
            "# Compliance Control Report",
            "",
            f"Generated: {self.generated_at}",
            "",
            "| Control | Description | Status | Evidence |",
            "|---|---|---|---|",
        ]
        for row in self.implemented:
            lines.append(f"| {row.control} | {row.description} | implemented | {row.evidence} |")
        for row in self.gaps:
            lines.append(f"| {row.control} | {row.description} | **gap** | {row.evidence} |")
        lines += [
            "",
            f"Coverage: {len(self.implemented)}/{len(self.implemented) + len(self.gaps)} "
            f"controls implemented ({self.coverage:.0%}).",
            "",
            "Gap rows are honest: they list what a real certification audit would flag.",
        ]
        return "\n".join(lines)


def generate_report() -> ComplianceReport:
    """Build the report from the implemented/gapped control tables above."""
    implemented = [
        ControlStatus(
            control=row["control"],
            framework=row["framework"],
            description=row["description"],
            status="implemented",
            evidence=row["implemented_by"],
        )
        for row in IMPLEMENTED_CONTROLS
    ]
    gaps = [
        ControlStatus(
            control=row["control"],
            framework=row["framework"],
            description=row["description"],
            status="gap",
            evidence=row["gap_reason"],
        )
        for row in GAPPED_CONTROLS
    ]
    total = len(implemented) + len(gaps)
    return ComplianceReport(
        generated_at=_now_iso(),
        implemented=implemented,
        gaps=gaps,
        coverage=round(len(implemented) / total, 3) if total else 0.0,
    )


def write_report(path: Path) -> Path:
    """Write Markdown + JSON reports; returns the Markdown path."""
    report = generate_report()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.to_markdown(), encoding="utf-8")
    path.with_suffix(".json").write_text(
        json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8"
    )
    return path


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


__all__ = ["ComplianceReport", "ControlStatus", "generate_report", "write_report"]
