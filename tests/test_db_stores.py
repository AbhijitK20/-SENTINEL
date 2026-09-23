"""SQLite-mode checks for dual-mode stores (one per store)."""

from pathlib import Path

from test_ledger import _forecast

from sentinel.cases import Case, CaseStore
from sentinel.db import Database
from sentinel.drift import DriftSnapshot
from sentinel.feedback import FeedbackStore
from sentinel.ledger import AlertLedger


def test_case_store_sqlite(tmp_path: Path) -> None:
    db = Database(tmp_path / "stores.db")
    store = CaseStore("unused.jsonl", db_path=str(tmp_path / "stores.db"))
    case = Case(
        case_id="C-1",
        incident_id="I-1",
        status="OPEN",
        assignee=None,
        risk_level="high",
        opened_at="2026-01-01T00:00:00+00:00",
        sla_due="2026-01-01T08:00:00+00:00",
        closed_at=None,
        notes=[],
    )
    store._append(case)
    reloaded = CaseStore("unused.jsonl", db_path=str(tmp_path / "stores.db"))._load()
    assert len(reloaded) == 1
    assert reloaded[0].case_id == "C-1"
    assert db is not None


def test_alert_ledger_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "stores.db"
    ledger = AlertLedger("unused.jsonl", db_path=str(path))
    ledger.append_forecast(_forecast(tmp_path))
    assert ledger.verify().valid

    ledger.tamper_latest_for_demo()
    assert not ledger.verify().valid

    ledger.reset()
    assert ledger.records() == []
    assert ledger.verify().valid


def test_feedback_store_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "stores.db"
    store = FeedbackStore("unused.jsonl", db_path=str(path))
    store.record("INC-1", "true_positive", "alice")
    loaded = FeedbackStore("unused.jsonl", db_path=str(path)).load()
    assert len(loaded) == 1
    assert loaded[0].verdict == "true_positive"


def test_drift_snapshot_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "stores.db"
    snap = DriftSnapshot("unused.jsonl", db_path=str(path))
    snap.capture({"cpu": [1.0, 2.0, 3.0], "mem": [40.0, 50.0]})
    reloaded = DriftSnapshot("unused.jsonl", db_path=str(path)).load()
    assert reloaded is not None
    assert reloaded == {"cpu": [1.0, 2.0, 3.0], "mem": [40.0, 50.0]}
