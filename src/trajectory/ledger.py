"""Tamper-evident forecast audit ledger.

This is a local, append-only ledger for the prototype. It deliberately stores
hashes and forecast metadata rather than raw traffic or PCAP contents. The
chained records demonstrate the integrity and provenance layer that can later
be backed by a permissioned blockchain without changing the forecast contract.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trajectory.schemas import Forecast

LEDGER_VERSION = "trajectory-ledger-v1"
GENESIS_HASH = "0" * 64


class AlertRecord(BaseModel):
    """One immutable forecast registration in the local ledger."""

    model_config = ConfigDict(extra="forbid")

    ledger_version: str = LEDGER_VERSION
    alert_id: str = Field(min_length=1)
    created_at: datetime
    status: str = "created"
    model_version: str = Field(min_length=1)
    predicted_stage: str = Field(min_length=1)
    probability: float = Field(ge=0.0, le=1.0)
    affected_entities: list[str] = Field(default_factory=list)
    evidence_hash: str = Field(min_length=64, max_length=64)
    forecast_hash: str = Field(min_length=64, max_length=64)
    previous_hash: str = Field(min_length=64, max_length=64)
    record_hash: str = Field(min_length=64, max_length=64)


class LedgerVerification(BaseModel):
    """Result of checking record order, hashes, and the chain link."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    records_checked: int = Field(ge=0)
    errors: list[str] = Field(default_factory=list)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Any) -> str:
    payload = value if isinstance(value, str) else _canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evidence_payload(forecast: Forecast) -> dict[str, Any]:
    """Return the evidence subset whose integrity should be independently checked."""
    return {
        "stage_mapping": forecast.stage_mapping.model_dump(mode="json")
        if forecast.stage_mapping
        else None,
        "affected_entities": forecast.affected_entities,
        "driving_features": [item.model_dump(mode="json") for item in forecast.driving_features],
        "supporting_events": forecast.supporting_events,
        "coverage": forecast.coverage,
        "warnings": forecast.warnings,
    }


def forecast_hash(forecast: Forecast) -> str:
    """Hash the complete typed forecast, including its probability timeline."""
    return _sha256(forecast.model_dump(mode="json"))


def evidence_hash(forecast: Forecast) -> str:
    """Hash the evidence presented alongside a forecast."""
    return _sha256(evidence_payload(forecast))


class AlertLedger:
    """Append-only JSONL ledger with a hash chain suitable for later anchoring."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append_forecast(self, forecast: Forecast, *, status: str = "created") -> AlertRecord:
        """Register a forecast and return the resulting tamper-evident record."""
        previous = self._last_record()
        previous_hash = previous.record_hash if previous else GENESIS_HASH
        alert_id = f"ALT-{secrets.token_hex(6).upper()}"
        payload = {
            "ledger_version": LEDGER_VERSION,
            "alert_id": alert_id,
            "created_at": datetime.now(tz=UTC).isoformat(),
            "status": status,
            "model_version": forecast.model_version,
            "predicted_stage": forecast.predicted_stage.name,
            "probability": forecast.predicted_stage.probability,
            "affected_entities": forecast.affected_entities,
            "evidence_hash": evidence_hash(forecast),
            "forecast_hash": forecast_hash(forecast),
            "previous_hash": previous_hash,
        }
        # Hash the same JSON-compatible representation that is later verified;
        # this avoids datetime normalization changing the signed payload.
        draft = AlertRecord(**payload, record_hash=GENESIS_HASH)
        record = draft.model_copy(
            update={
                "record_hash": _sha256(
                    draft.model_dump(mode="json", exclude={"record_hash"})
                )
            }
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
        return record

    def verify(self) -> LedgerVerification:
        """Verify every JSONL record and every link to its predecessor."""
        if not self.path.exists():
            return LedgerVerification(valid=True, records_checked=0)

        errors: list[str] = []
        records: list[AlertRecord] = []
        for line_number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(AlertRecord.model_validate_json(line))
            except Exception as error:
                errors.append(f"line {line_number}: invalid record ({error})")

        expected_previous = GENESIS_HASH
        for index, record in enumerate(records, 1):
            payload = record.model_dump(mode="json", exclude={"record_hash"})
            if record.record_hash != _sha256(payload):
                errors.append(f"record {index} ({record.alert_id}): record hash mismatch")
            if record.previous_hash != expected_previous:
                errors.append(f"record {index} ({record.alert_id}): broken previous-hash link")
            expected_previous = record.record_hash

        return LedgerVerification(
            valid=not errors,
            records_checked=len(records),
            errors=errors,
        )

    def tamper_latest_for_demo(self) -> bool:
        """Alter the latest record for the UI's integrity-failure demonstration.

        This intentionally changes the stored record hash without updating the
        signed payload. It is a demo-only operation and returns ``False`` when
        there is no record to tamper with.
        """
        if not self.path.exists():
            return False
        lines = self.path.read_text(encoding="utf-8").splitlines()
        for index in range(len(lines) - 1, -1, -1):
            if not lines[index].strip():
                continue
            try:
                payload = json.loads(lines[index])
            except json.JSONDecodeError:
                return False
            current_hash = str(payload.get("record_hash", ""))
            replacement_hash = "f" * 64 if current_hash != "f" * 64 else "e" * 64
            payload["record_hash"] = replacement_hash
            lines[index] = _canonical_json(payload)
            self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return True
        return False

    def reset(self) -> None:
        """Clear the local demo ledger so a new integrity demonstration can start."""
        self.path.unlink(missing_ok=True)

    def records(self) -> list[AlertRecord]:
        """Read validly-shaped records for display; use verify() for integrity."""
        if not self.path.exists():
            return []
        records: list[AlertRecord] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(AlertRecord.model_validate_json(line))
            except Exception:
                # verify() reports malformed lines; the dashboard should still
                # render and let the user repair or reset the demo ledger.
                continue
        return records

    def _last_record(self) -> AlertRecord | None:
        records = self.records()
        return records[-1] if records else None


__all__ = [
    "AlertLedger",
    "AlertRecord",
    "GENESIS_HASH",
    "LEDGER_VERSION",
    "LedgerVerification",
    "evidence_hash",
    "evidence_payload",
    "forecast_hash",
]
