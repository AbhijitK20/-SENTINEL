"""Sentinel-controlled IP blocklist.

The vulnerable app checks this before processing any request; the admin
dashboard adds/removes entries.  Stored in an append-only JSONL so every
ban/unban action is auditable.
"""

from __future__ import annotations

import hashlib  # noqa: F401 — imported for future HMAC signing of entries
import json
import time

from paths import BLOCKLIST as BLOCKLIST_PATH

_blocked: dict[str, dict] = {}
_loaded = False
_mtime: float | None = None


def _load() -> None:
    """Reload when the file changes, so bans written by the admin container apply."""
    global _loaded, _mtime
    mtime = BLOCKLIST_PATH.stat().st_mtime if BLOCKLIST_PATH.exists() else None
    if _loaded and mtime == _mtime:
        return
    _blocked.clear()
    if mtime is not None:
        for line in BLOCKLIST_PATH.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            ip = rec["ip"]
            if rec.get("action") == "ban":
                _blocked[ip] = rec
            elif rec.get("action") == "unban":
                _blocked.pop(ip, None)
    _loaded = True
    _mtime = mtime


def is_blocked(ip: str) -> bool:
    _load()
    return ip in _blocked


def ban(ip: str, *, reason: str = "", source: str = "admin") -> dict:
    _load()
    rec = {
        "ip": ip,
        "action": "ban",
        "reason": reason,
        "source": source,
        "ts": time.time(),
    }
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    _blocked[ip] = rec
    return rec


def unban(ip: str, *, source: str = "admin") -> dict:
    _load()
    rec = {
        "ip": ip,
        "action": "unban",
        "reason": "",
        "source": source,
        "ts": time.time(),
    }
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    _blocked.pop(ip, None)
    return rec


def list_blocked() -> list[dict]:
    _load()
    return list(_blocked.values())
