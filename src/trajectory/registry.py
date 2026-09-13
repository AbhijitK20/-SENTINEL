"""Model registry (roadmap Phase 7): versioned model records with approval.

Scope honesty: this is a local JSON-backed registry demonstrating the
promotion workflow (registered -> approved -> rolled-back). MLflow, shadow
deployment, and A/B evaluation need production infrastructure and are
documented as future work in ROADMAP.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RegistryStatus = Literal["registered", "approved", "rolled_back"]


class ModelRecord(BaseModel):
    """One registered model version with its lineage and approval state."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    checksum: str = Field(min_length=8)
    feature_schema_version: str = Field(min_length=1)
    threshold: float = Field(ge=0.0, le=1.0)
    training_dataset: str = Field(min_length=1)
    status: RegistryStatus = "registered"
    approved_by: str | None = None
    notes: str = ""


class ModelRegistry:
    """JSON-backed registry; ``approve`` and ``rollback`` are explicit steps."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def register(
        self,
        name: str,
        *,
        version: str,
        checksum: str,
        feature_schema_version: str,
        threshold: float,
        training_dataset: str,
        notes: str = "",
    ) -> ModelRecord:
        record = ModelRecord(
            name=name,
            version=version,
            checksum=checksum,
            feature_schema_version=feature_schema_version,
            threshold=threshold,
            training_dataset=training_dataset,
            notes=notes,
        )
        self._append(record)
        return record

    def _append(self, record: ModelRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.model_dump(mode="json")) + "\n")

    def _load(self) -> list[ModelRecord]:
        if not self.path.exists():
            return []
        return [
            ModelRecord.model_validate_json(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _latest(self, name: str, version: str) -> ModelRecord:
        matches = [r for r in self._load() if r.name == name and r.version == version]
        if not matches:
            raise KeyError(f"unknown model version: {name}@{version}")
        return matches[-1]

    def approve(self, name: str, version: str, *, approver: str) -> ModelRecord:
        """Approve a registered version for serving."""
        record = self._latest(name, version)
        if record.status != "registered":
            raise ValueError(f"{name}@{version} is {record.status}, not registered")
        updated = record.model_copy(update={"status": "approved", "approved_by": approver})
        self._append(updated)
        return updated

    def rollback(self, name: str, version: str) -> ModelRecord:
        """Roll a previously approved version back (e.g. after drift or regression)."""
        record = self._latest(name, version)
        if record.status != "approved":
            raise ValueError(f"{name}@{version} is {record.status}, not approved")
        updated = record.model_copy(update={"status": "rolled_back"})
        self._append(updated)
        return updated

    def latest_status(self, name: str, version: str) -> ModelRecord:
        """Current state of one version (fold over the append log)."""
        return self._latest(name, version)

    def list_models(self) -> list[dict[str, str]]:
        """Latest record per (name, version), append-order preserved."""
        latest: dict[tuple[str, str], ModelRecord] = {}
        for record in self._load():
            latest[(record.name, record.version)] = record
        return [
            {"name": n, "version": v, "status": r.status, "checksum": r.checksum}
            for (n, v), r in latest.items()
        ]


__all__ = ["ModelRecord", "ModelRegistry", "RegistryStatus"]
