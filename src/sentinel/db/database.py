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
                metadata TEXT,
                expires_at TEXT
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

            CREATE TABLE IF NOT EXISTS store_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                store TEXT NOT NULL,
                record TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_log(key_id);
            CREATE INDEX IF NOT EXISTS idx_store_log_store ON store_log(store, id);
            """
        )
        # CREATE TABLE IF NOT EXISTS won't add columns to an existing DB.
        try:
            self.conn.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
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

    # ── Generic append-only store log ─────────────────────────────────
    # One table backs every JSONL-shaped store (cases, ledger, feedback,
    # drift). Stores partition by `store` name; `record` holds the exact
    # JSON that the JSONL store would have written, so Pydantic
    # round-trips are identical across modes.

    def log_append(self, store: str, record_json: str) -> None:
        self.execute(
            "INSERT INTO store_log (store, record) VALUES (?, ?)",
            (store, record_json),
        )
        self.commit()

    def log_all(self, store: str) -> list[str]:
        rows = self.fetchall(
            "SELECT record FROM store_log WHERE store = ? ORDER BY id",
            (store,),
        )
        return [r["record"] for r in rows]

    def log_clear(self, store: str) -> None:
        self.execute("DELETE FROM store_log WHERE store = ?", (store,))
        self.commit()

    def log_update_latest(self, store: str, record_json: str) -> bool:
        """Overwrite the newest record in `store` (ledger tamper demo)."""
        row = self.fetchone(
            "SELECT id FROM store_log WHERE store = ? ORDER BY id DESC LIMIT 1",
            (store,),
        )
        if row is None:
            return False
        self.execute("UPDATE store_log SET record = ? WHERE id = ?", (record_json, row["id"]))
        self.commit()
        return True

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


__all__ = ["Database"]
