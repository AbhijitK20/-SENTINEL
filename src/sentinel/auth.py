# SPDX-License-Identifier: Apache-2.0
"""API-key authentication, roles, and audit logging (roadmap Phase 2).

Scope honesty: this is key-based auth for services and analysts over the
REST API. SSO/OIDC, MFA, and multi-tenancy are NOT implemented — they need a
real identity provider and stay listed as future work in docs/ROADMAP.md.

Design rules:
- Raw keys are shown once at creation; only SHA-256 hashes are stored.
- Roles are a fixed set with an explicit permission matrix — no wildcards.
- The audit log is append-only JSONL; records are never edited or deleted.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

ROLES = ("viewer", "analyst", "engineer", "admin")

# Explicit permission matrix. Endpoint patterns are prefix-matched against
# "METHOD /path"; nothing outside this table is permitted.
PERMISSIONS: dict[str, tuple[str, ...]] = {
    "viewer": ("GET /health", "GET /model", "GET /v1/cases", "GET /v1/compliance"),
    "analyst": (
        "GET /health",
        "GET /model",
        "POST /v1/forecast",
        "POST /v1/detect",
        "POST /v1/events",
        "GET /v1/alerts",
        "POST /v1/alerts",
        "GET /v1/cases",
        "POST /v1/cases",
        "GET /v1/compliance",
    ),
    "engineer": (
        "GET /health",
        "GET /model",
        "POST /v1/forecast",
        "POST /v1/detect",
        "POST /v1/events",
        "GET /v1/alerts",
        "POST /v1/alerts",
        "GET /v1/cases",
        "POST /v1/cases",
        "GET /v1/compliance",
        "GET /v1/registry",
        "POST /v1/drift",
        "GET /metrics",
        "GET /admin/keys",
    ),
    "admin": ("*",),
}

KEY_PREFIX = "sent_"


class ApiKeyRecord(BaseModel):
    """Stored (hashed) API key metadata. Never contains the raw key."""

    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(min_length=1)
    key_hash: str = Field(min_length=64, max_length=64)
    role: str
    org_id: str = "default"
    label: str = ""
    created_at: datetime
    expires_at: datetime | None = None
    revoked: bool = False


class AuditRecord(BaseModel):
    """One authenticated API action, appended to the audit trail."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    key_id: str
    role: str
    org_id: str = "-"
    method: str
    path: str
    status_code: int
    client: str


def hash_key(raw_key: str) -> str:
    """SHA-256 of the raw key — the only form ever persisted."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _expired(expires_at: datetime | None) -> bool:
    """True when the timestamp is in the past; naive values are treated as UTC."""
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= _now()


class ApiKeyStore:
    """API key store with hashed keys and revocation.

    Supports both JSONL (default, for backward compatibility) and SQLite
    persistence. Set ``db_path`` to enable SQLite mode.
    """

    def __init__(self, path: Path, *, db_path: str | None = None) -> None:
        self.path = Path(path)
        self._db = None
        if db_path:
            from sentinel.db import Database

            self._db = Database(db_path)

    # ── persistence ──────────────────────────────────────────────────
    def _read_all(self) -> list[ApiKeyRecord]:
        if self._db:
            rows = self._db.fetchall("SELECT * FROM api_keys ORDER BY rowid")
            return [
                ApiKeyRecord(
                    key_id=r["key_id"],
                    key_hash=r["key_hash"],
                    role=r["role"],
                    label=r.get("label", ""),
                    org_id=r.get("org_id", "default"),
                    created_at=r["created_at"],
                    expires_at=r.get("expires_at"),
                    revoked=bool(r.get("revoked")),
                )
                for r in rows
            ]
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(ApiKeyRecord.model_validate_json(line))
        return records

    def _append(self, record: ApiKeyRecord) -> None:
        if self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO api_keys "
                "(key_id, role, key_hash, label, org_id, created_at, expires_at, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.key_id,
                    record.role,
                    record.key_hash,
                    record.label,
                    record.org_id,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat() if record.expires_at else None,
                    int(record.revoked),
                ),
            )
            self._db.commit()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.model_dump(mode="json")) + "\n")

    # ── lifecycle ────────────────────────────────────────────────────
    def create(
        self,
        role: str,
        *,
        label: str = "",
        expires_at: datetime | None = None,
        org_id: str = "default",
    ) -> tuple[str, ApiKeyRecord]:
        """Create a key; returns ``(raw_key, record)`` — raw key shown once."""
        if role not in ROLES:
            raise ValueError(f"unknown role: {role} (valid: {', '.join(ROLES)})")
        raw = KEY_PREFIX + secrets.token_urlsafe(32)
        record = ApiKeyRecord(
            key_id=raw[:14],
            key_hash=hash_key(raw),
            role=role,
            org_id=org_id,
            label=label,
            created_at=_now(),
            expires_at=expires_at,
        )
        self._append(record)
        return raw, record

    def register_raw(
        self,
        raw_key: str,
        role: str,
        *,
        label: str = "",
        org_id: str = "default",
    ) -> ApiKeyRecord:
        """Register a deployer-chosen raw key (bootstrap/admin provisioning).

        Unlike :meth:`create`, the raw value is supplied by the operator (e.g.
        via the SENTINEL_BOOTSTRAP_KEY env var) so the very first admin key
        can be provisioned without an existing key. Same storage rules apply:
        only the SHA-256 hash is persisted.
        """
        if role not in ROLES:
            raise ValueError(f"unknown role: {role} (valid: {', '.join(ROLES)})")
        record = ApiKeyRecord(
            key_id=raw_key[:14],
            key_hash=hash_key(raw_key),
            role=role,
            org_id=org_id,
            label=label,
            created_at=_now(),
        )
        self._append(record)
        return record

    def revoke(self, key_id: str) -> bool:
        """Mark a key revoked; returns False if the id is unknown/already revoked."""
        latest: dict[str, ApiKeyRecord] = {}
        for record in self._read_all():
            if record.key_id == key_id:
                latest[record.key_id] = record
        target = latest.get(key_id)
        if target is None or target.revoked:
            return False
        self._append(target.model_copy(update={"revoked": True}))
        return True

    def authenticate(self, raw_key: str) -> ApiKeyRecord:
        """Resolve a raw key to an active record; raises PermissionError.

        Records are folded to the latest state per key_id first, so a
        revocation always wins over the original create record.
        """
        matched = hash_key(raw_key)
        latest: dict[str, ApiKeyRecord] = {}
        for record in self._read_all():
            if record.key_hash == matched:
                latest[record.key_id] = record
        for record in latest.values():
            if record.revoked:
                raise PermissionError("key has been revoked")
            if _expired(record.expires_at):
                raise PermissionError("key has expired")
            return record
        raise PermissionError("unknown API key")

    def list_active(self) -> list[ApiKeyRecord]:
        """Active (latest-state) records: revocations applied, expired excluded."""
        latest: dict[str, ApiKeyRecord] = {}
        for record in self._read_all():
            latest[record.key_id] = record
        return [
            record
            for record in latest.values()
            if not record.revoked and not _expired(record.expires_at)
        ]


def role_can(role: str, method: str, path: str) -> bool:
    """Check the permission matrix (prefix match, admin wildcard)."""
    allowed = PERMISSIONS.get(role, ())
    if "*" in allowed:
        return True
    request = f"{method} {path}"
    return any(request == entry or request.startswith(entry + "/") for entry in allowed)


class AuditLog:
    """Append-only audit trail for authenticated API actions.

    Supports both JSONL (default) and SQLite persistence.
    """

    def __init__(self, path: Path, *, db_path: str | None = None) -> None:
        self.path = Path(path)
        self._db = None
        if db_path:
            from sentinel.db import Database

            self._db = Database(db_path)

    def record(
        self,
        *,
        key_id: str,
        role: str,
        method: str,
        path: str,
        status_code: int,
        client: str,
        org_id: str = "-",
    ) -> AuditRecord:
        entry = AuditRecord(
            timestamp=_now(),
            key_id=key_id,
            role=role,
            org_id=org_id,
            method=method,
            path=path,
            status_code=status_code,
            client=client,
        )
        if self._db:
            self._db.execute(
                "INSERT INTO audit_log "
                "(timestamp, key_id, role, action, resource, status, client_ip, org_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.timestamp,
                    entry.key_id,
                    entry.role,
                    entry.method,
                    entry.path,
                    str(entry.status_code),
                    entry.client,
                    entry.org_id,
                ),
            )
            self._db.commit()
            return entry
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry.model_dump(mode="json")) + "\n")
        return entry

    def load(self) -> list[AuditRecord]:
        if self._db:
            return [
                AuditRecord(
                    timestamp=r["timestamp"],
                    key_id=r["key_id"],
                    role=r["role"],
                    org_id=r.get("org_id", "-"),
                    method=r["action"],
                    path=r["resource"],
                    status_code=int(r.get("status", 0)),
                    client=r.get("client_ip", ""),
                )
                for r in self._db.fetchall("SELECT * FROM audit_log ORDER BY id")
            ]
        if not self.path.exists():
            return []
        return [
            AuditRecord.model_validate_json(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


__all__ = [
    "AuditLog",
    "AuditRecord",
    "ApiKeyRecord",
    "ApiKeyStore",
    "PERMISSIONS",
    "ROLES",
    "hash_key",
    "role_can",
]
