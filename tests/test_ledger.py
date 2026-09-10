"""Tests for the tamper-evident forecast ledger."""

from __future__ import annotations

from pathlib import Path

from test_predict import _build_artifact_paths

from trajectory.ledger import GENESIS_HASH, AlertLedger, evidence_hash, forecast_hash
from trajectory.predict import forecast


def _forecast(tmp_path: Path):
    baseline_dir, _, states = _build_artifact_paths(tmp_path)
    from trajectory.predict import load_artifacts

    return forecast(states, load_artifacts(baseline_dir), max_horizon=2)


def test_ledger_records_and_verifies_forecast(tmp_path: Path) -> None:
    result = _forecast(tmp_path)
    ledger = AlertLedger(tmp_path / "alerts.jsonl")

    record = ledger.append_forecast(result)

    assert record.previous_hash == GENESIS_HASH
    assert record.forecast_hash == forecast_hash(result)
    assert record.evidence_hash == evidence_hash(result)
    verification = ledger.verify()
    assert verification.valid
    assert verification.records_checked == 1


def test_ledger_detects_tampering(tmp_path: Path) -> None:
    result = _forecast(tmp_path)
    path = tmp_path / "alerts.jsonl"
    ledger = AlertLedger(path)
    ledger.append_forecast(result)

    content = path.read_text(encoding="utf-8")
    path.write_text(content.replace('"status":"created"', '"status":"resolved"'), encoding="utf-8")

    verification = ledger.verify()
    assert not verification.valid
    assert any("hash mismatch" in error for error in verification.errors)


def test_ledger_demo_tampering_changes_latest_record(tmp_path: Path) -> None:
    result = _forecast(tmp_path)
    ledger = AlertLedger(tmp_path / "alerts.jsonl")
    ledger.append_forecast(result)

    assert ledger.tamper_latest_for_demo()
    verification = ledger.verify()
    assert not verification.valid
    assert any("hash mismatch" in error for error in verification.errors)
    assert ledger.tamper_latest_for_demo()


def test_ledger_chains_records(tmp_path: Path) -> None:
    result = _forecast(tmp_path)
    ledger = AlertLedger(tmp_path / "alerts.jsonl")

    first = ledger.append_forecast(result)
    second = ledger.append_forecast(result)

    assert second.previous_hash == first.record_hash
    assert ledger.verify().valid


def test_ledger_reset_removes_demo_records(tmp_path: Path) -> None:
    result = _forecast(tmp_path)
    ledger = AlertLedger(tmp_path / "alerts.jsonl")
    ledger.append_forecast(result)

    ledger.reset()

    assert not ledger.path.exists()
    assert ledger.verify().valid
    assert ledger.verify().records_checked == 0
