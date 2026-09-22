"""SQLite persistence layer for SENTINEL.

Replaces JSONL stores with SQLite for production use.
Thread-safe, WAL mode, with proper schema migration.

Usage:
    from sentinel.db import Database
    db = Database("sentinel.db")
    db.init_schema()
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class Database:
    """Thread-safe SQLite wrapper with WAL mode."""

    def __init__(self, path: str | Path = "sentinel.db"):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self.init_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=10)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                label TEXT,
                key_hash TEXT NOT NULL,
                org_id TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked INTEGER DEFAULT 0,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                key_id TEXT,
                role TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                status TEXT,
                client_ip TEXT,
                org_id TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'OPEN',
                severity TEXT NOT NULL DEFAULT 'medium',
                title TEXT,
                description TEXT,
                assigned_to TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                sla_deadline TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                model_version TEXT,
                predicted_stage TEXT,
                probability REAL,
                affected_entities TEXT,
                evidence_hash TEXT,
                forecast_hash TEXT,
                previous_hash TEXT,
                record_hash TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_id TEXT,
                analyst TEXT,
                verdict TEXT,
                reasoning TEXT,
                hmac_signature TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS drift (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                feature_name TEXT NOT NULL,
                psi_value REAL,
                baseline_mean REAL,
                baseline_std REAL,
                current_mean REAL,
                current_std REAL,
                metadata TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_log(key_id);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
            CREATE INDEX IF NOT EXISTS idx_feedback_alert ON feedback(alert_id);
            CREATE INDEX IF NOT EXISTS idx_drift_feature ON drift(feature_name);
            """
        )
        self.conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, params: list[tuple]) -> None:
        self.conn.executemany(sql, params)
        self.conn.commit()

    def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(row) for row in self.conn.execute(sql, params)]

    def commit(self) -> None:
        self.conn.commit()

    # ── API Keys ──────────────────────────────────────────────────────

    def create_key(
        self,
        key_id: str,
        role: str,
        key_hash: str,
        label: str = "",
        org_id: str = "",
        metadata: dict | None = None,
    ) -> dict:
        now = datetime.now(tz=UTC).isoformat()
        self.execute(
            "INSERT INTO api_keys "
            "(key_id, role, key_hash, label, org_id, created_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (key_id, role, key_hash, label, org_id, now, json.dumps(metadata or {})),
        )
        self.commit()
        return {"key_id": key_id, "role": role, "label": label, "created_at": now}

    def authenticate(self, key_hash: str) -> dict | None:
        row = self.fetchone(
            "SELECT key_id, role, label, org_id FROM api_keys WHERE key_hash = ? AND revoked = 0",
            (key_hash,),
        )
        if row:
            self.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
                (datetime.now(tz=UTC).isoformat(), row["key_id"]),
            )
            self.commit()
        return row

    def revoke_key(self, key_id: str) -> bool:
        cursor = self.execute("UPDATE api_keys SET revoked = 1 WHERE key_id = ?", (key_id,))
        self.commit()
        return cursor.rowcount > 0

    # ── Audit Log ─────────────────────────────────────────────────────

    def audit(
        self,
        action: str,
        key_id: str = "",
        role: str = "",
        resource: str = "",
        status: str = "ok",
        client_ip: str = "",
        org_id: str = "",
        metadata: dict | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO audit_log "
            "(timestamp, key_id, role, action, resource, status, client_ip, org_id, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(tz=UTC).isoformat(),
                key_id,
                role,
                action,
                resource,
                status,
                client_ip,
                org_id,
                json.dumps(metadata or {}),
            ),
        )
        self.commit()

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        return self.fetchall("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    # ── Cases ─────────────────────────────────────────────────────────

    def create_case(
        self,
        case_id: str,
        title: str,
        severity: str = "medium",
        description: str = "",
        metadata: dict | None = None,
    ) -> dict:
        now = datetime.now(tz=UTC).isoformat()
        self.execute(
            "INSERT INTO cases "
            "(case_id, title, severity, description, created_at, updated_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, title, severity, description, now, now, json.dumps(metadata or {})),
        )
        self.commit()
        return {"case_id": case_id, "status": "OPEN", "severity": severity}

    def get_case(self, case_id: str) -> dict | None:
        return self.fetchone("SELECT * FROM cases WHERE case_id = ?", (case_id,))

    def update_case(self, case_id: str, **kwargs: Any) -> bool:
        allowed = {"status", "severity", "title", "assigned_to", "resolved_at", "metadata"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        updates["updated_at"] = datetime.now(tz=UTC).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [case_id]
        cursor = self.execute(f"UPDATE cases SET {set_clause} WHERE case_id = ?", tuple(values))
        self.commit()
        return cursor.rowcount > 0

    def list_cases(self, status: str | None = None, limit: int = 100) -> list[dict]:
        if status:
            return self.fetchall(
                "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            )
        return self.fetchall("SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,))

    # ── Alerts (Hash Chain Ledger) ────────────────────────────────────

    def append_alert(
        self,
        alert_id: str,
        record_hash: str,
        previous_hash: str,
        model_version: str = "",
        predicted_stage: str = "",
        probability: float = 0.0,
        affected_entities: list[str] | None = None,
        evidence_hash: str = "",
        forecast_hash: str = "",
        metadata: dict | None = None,
    ) -> dict:
        now = datetime.now(tz=UTC).isoformat()
        self.execute(
            "INSERT INTO alerts "
            "(alert_id, created_at, model_version, predicted_stage, probability, "
            "affected_entities, evidence_hash, forecast_hash, previous_hash, "
            "record_hash, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert_id,
                now,
                model_version,
                predicted_stage,
                probability,
                json.dumps(affected_entities or []),
                evidence_hash,
                forecast_hash,
                previous_hash,
                record_hash,
                json.dumps(metadata or {}),
            ),
        )
        self.commit()
        return {"alert_id": alert_id, "created_at": now}

    def get_alerts(self, limit: int = 100) -> list[dict]:
        return self.fetchall("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    def verify_alert_chain(self) -> list[str]:
        errors = []
        records = self.fetchall("SELECT * FROM alerts ORDER BY id ASC")
        prev_hash = "0" * 64
        for i, rec in enumerate(records):
            if rec["previous_hash"] != prev_hash:
                errors.append(f"record {i} ({rec['alert_id']}): broken chain")
            prev_hash = rec["record_hash"]
        return errors

    # ── Feedback ──────────────────────────────────────────────────────

    def record_feedback(
        self,
        alert_id: str,
        analyst: str,
        verdict: str,
        reasoning: str = "",
        hmac_signature: str = "",
        metadata: dict | None = None,
    ) -> None:
        now = datetime.now(tz=UTC).isoformat()
        self.execute(
            "INSERT INTO feedback "
            "(timestamp, alert_id, analyst, verdict, reasoning, hmac_signature, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                now,
                alert_id,
                analyst,
                verdict,
                reasoning,
                hmac_signature,
                json.dumps(metadata or {}),
            ),
        )
        self.commit()

    def get_feedback(self, alert_id: str | None = None, limit: int = 100) -> list[dict]:
        if alert_id:
            return self.fetchall(
                "SELECT * FROM feedback WHERE alert_id = ? ORDER BY id DESC LIMIT ?",
                (alert_id, limit),
            )
        return self.fetchall("SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (limit,))

    # ── Drift Monitoring ──────────────────────────────────────────────

    def record_drift(
        self,
        feature_name: str,
        psi_value: float,
        baseline_mean: float = 0,
        baseline_std: float = 0,
        current_mean: float = 0,
        current_std: float = 0,
        metadata: dict | None = None,
    ) -> None:
        now = datetime.now(tz=UTC).isoformat()
        self.execute(
            "INSERT INTO drift "
            "(timestamp, feature_name, psi_value, baseline_mean, baseline_std, "
            "current_mean, current_std, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                now,
                feature_name,
                psi_value,
                baseline_mean,
                baseline_std,
                current_mean,
                current_std,
                json.dumps(metadata or {}),
            ),
        )
        self.commit()

    def get_drift(self, feature_name: str | None = None, limit: int = 100) -> list[dict]:
        if feature_name:
            return self.fetchall(
                "SELECT * FROM drift WHERE feature_name = ? ORDER BY id DESC LIMIT ?",
                (feature_name, limit),
            )
        return self.fetchall("SELECT * FROM drift ORDER BY id DESC LIMIT ?", (limit,))

    # ── Export ─────────────────────────────────────────────────────────

    def export_jsonl(self, table: str, path: str | Path) -> int:
        rows = self.fetchall(f"SELECT * FROM {table}")
        lines = [json.dumps(row) for row in rows]
        Path(path).write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")
        return len(rows)
