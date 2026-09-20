"""Regression tests for the demo blocklist shared by the app and admin containers.

The blocklist lives on the shared ``/logs`` volume; the vulnerable app must pick
up bans/unbans written by the admin container without a restart.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parents[1] / "apps" / "vulnerable"


def _import_blocklist(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SENTINEL_BLOCKLIST", str(tmp_path / "blocklist.jsonl"))
    monkeypatch.syspath_prepend(str(DEMO_DIR))
    sys.modules.pop("paths", None)
    sys.modules.pop("blocklist", None)
    return importlib.import_module("blocklist")


def test_blocklist_path_comes_from_env(tmp_path: Path, monkeypatch) -> None:
    paths = None
    try:
        monkeypatch.setenv("SENTINEL_BLOCKLIST", str(tmp_path / "b.jsonl"))
        monkeypatch.syspath_prepend(str(DEMO_DIR))
        sys.modules.pop("paths", None)
        paths = importlib.import_module("paths")
        assert paths.BLOCKLIST == tmp_path / "b.jsonl"
    finally:
        if paths is not None:
            sys.modules.pop("paths", None)


def test_external_unban_is_picked_up_without_restart(tmp_path: Path, monkeypatch) -> None:
    blocklist = _import_blocklist(monkeypatch, tmp_path)
    blocklist.ban("203.0.113.7", reason="test")
    assert blocklist.is_blocked("203.0.113.7")

    # Simulate the admin container appending an unban after the app's cached read.
    path = blocklist.BLOCKLIST_PATH
    with open(path, "a") as f:
        f.write(json.dumps({"ip": "203.0.113.7", "action": "unban"}) + "\n")
    stat = path.stat()
    os.utime(path, (stat.st_atime, stat.st_mtime + 1))

    assert not blocklist.is_blocked("203.0.113.7")
