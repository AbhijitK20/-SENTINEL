# SPDX-License-Identifier: Apache-2.0
"""Evaluation gates for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class GateStatus(Enum):
    """Evaluation gate status."""

    PASS = "pass"
    FAIL = "fail"
    PENDING = "pending"


@dataclass
class GateResult:
    """Single gate result."""

    name: str
    status: GateStatus
    value: float | None = None
    threshold: float | None = None
    message: str = ""


@dataclass
class EvaluationGates:
    """Automated evaluation gates for model promotion."""

    gates: list[GateResult] = field(default_factory=list)

    def add_gate(self, result: GateResult) -> None:
        """Add a gate result."""
        self.gates.append(result)

    def check_all_passed(self) -> bool:
        """Check if all gates passed."""
        return all(g.status == GateStatus.PASS for g in self.gates)

    def get_failures(self) -> list[GateResult]:
        """Get all failed gates."""
        return [g for g in self.gates if g.status == GateStatus.FAIL]

    def to_dict(self) -> list[dict[str, str]]:
        """Convert to list of dicts."""
        return [
            {
                "name": g.name,
                "status": g.status.value,
                "message": g.message,
            }
            for g in self.gates
        ]
