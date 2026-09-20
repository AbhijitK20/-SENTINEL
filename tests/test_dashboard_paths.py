"""Regression: dashboard paths must resolve to the repo root, not ``src/``.

A ROOT one level short made the Force Attack buttons fail inside the container
(``ModuleNotFoundError: No module named 'apps'``), broke the local demo scripts,
and pointed the CIC dataset lookup at a non-existent ``src/data``.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = REPO_ROOT / "src" / "sentinel" / "dashboard"


def test_dashboard_root_is_repo_root() -> None:
    from sentinel.dashboard import state
    from sentinel.dashboard.tabs import live

    assert state.ROOT == REPO_ROOT
    assert state.REPORTS_DIR == REPO_ROOT / "reports" / "generated"
    assert live.ROOT == REPO_ROOT


def test_app_root_is_repo_root_in_source() -> None:
    """app.py runs as a Streamlit script; assert its ROOT expression directly."""
    source = (DASHBOARD / "app.py").read_text(encoding="utf-8")
    match = re.search(r"^ROOT = (.+)$", source, re.MULTILINE)
    assert match is not None, "ROOT assignment not found in app.py"
    assert "parents[3]" in match.group(1), match.group(1)
