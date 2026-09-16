# SPDX-License-Identifier: Apache-2.0
"""Case management (roadmap Phase 10): incident lifecycle with SLA tracking.

Cases wrap correlated incidents in an analyst-owned lifecycle: OPEN ->
ACKNOWLEDGED -> INVESTIGATING -> RESOLVED. SLA hours come from the incident
risk level. Append-only JSONL storage keeps every transition auditable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CaseStatus = Literal["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"]

SLA_HOURS = {"critical": 4.0, "high": 8.0, "medium": 24.0, "low": 72.0, "info": 168.0}
DEFAULT_SLA_HOURS = 168.0

ALLOWED: dict[str, tuple[str, ...]] = {
    "OPEN": ("ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"),
    "ACKNOWLEDGED": ("INVESTIGATING", "RESOLVED"),
    "INVESTIGATING": ("RESOLVED",),
    "RESOLVED": (),
}


class Case(BaseModel):
    """One analyst-owned case wrapping a correlated incident."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    status: CaseStatus = "OPEN"
    assignee: str | None = None
    risk_level: str = Field(min_length=1)
    opened_at: datetime
    sla_due: datetime
    closed_at: datetime | None = None
    notes: list[str] = Field(default_factory=list)


class CaseStore:
    """Append-only JSONL case log; the latest record per case_id is current."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _append(self, case: Case) -> Case:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(case.model_dump(mode="json")) + "\n")
        return case

    def _load(self) -> list[Case]:
        if not self.path.exists():
            return []
        return [
            Case.model_validate_json(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def open_case(
        self,
        incident_id: str,
        risk_level: str,
        *,
        assignee: str | None = None,
        now: datetime | None = None,
    ) -> Case:
        now = now or datetime.now(UTC)
        case_id = f"CASE-{len(self.list_cases()) + 1:04d}"
        case = Case(
            case_id=case_id,
            incident_id=incident_id,
            risk_level=risk_level,
            opened_at=now,
            sla_due=now + timedelta(hours=SLA_HOURS.get(risk_level, DEFAULT_SLA_HOURS)),
            assignee=assignee,
        )
        return self._append(case)

    def get(self, case_id: str) -> Case | None:
        current: Case | None = None
        for record in self._load():
            if record.case_id == case_id:
                current = record
        return current

    def list_cases(self) -> list[Case]:
        latest: dict[str, Case] = {}
        for record in self._load():
            latest[record.case_id] = record
        return list(latest.values())

    def transition(
        self,
        case_id: str,
        to_status: CaseStatus,
        *,
        actor: str | None = None,
        now: datetime | None = None,
    ) -> Case:
        current = self.get(case_id)
        if current is None:
            raise KeyError(f"unknown case: {case_id}")
        if to_status not in ALLOWED[current.status]:
            raise ValueError(f"cannot move {current.status} -> {to_status}")
        now = now or datetime.now(UTC)
        note = f"{current.status} -> {to_status} by {actor or 'analyst'} at {now.isoformat()}"
        updated = current.model_copy(
            update={
                "status": to_status,
                "closed_at": now if to_status == "RESOLVED" else None,
                "notes": [*current.notes, note],
            }
        )
        return self._append(updated)

    def sla_report(self, *, now: datetime | None = None) -> dict[str, int]:
        """Counts of open cases by SLA state: on_track, breached, resolved."""
        now = now or datetime.now(UTC)
        report = {"on_track": 0, "breached": 0, "resolved": 0}
        for case in self.list_cases():
            if case.status == "RESOLVED":
                report["resolved"] += 1
            elif case.sla_due < now:
                report["breached"] += 1
            else:
                report["on_track"] += 1
        return report


__all__ = ["Case", "CaseStore", "CaseStatus", "SLA_HOURS"]
