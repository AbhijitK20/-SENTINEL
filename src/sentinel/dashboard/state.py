# SPDX-License-Identifier: Apache-2.0
"""Session-state helpers and cache invalidation for the SENTINEL dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.baseline import BaselineRun
    from sentinel.predict import LoadedArtifacts
    from sentinel.targets import FeatureSchema, SplitManifest
    from sentinel.temporal import TemporalRun


ROOT = Path(__file__).resolve().parents[3]
REPORTS_DIR = ROOT / "reports" / "generated"
LEDGER_PATH = REPORTS_DIR / "ledger" / "alerts.jsonl"
LOCAL_ATTACK_SPEED = 2.0


@dataclass(frozen=True)
class DashboardContext:
    """Immutable context passed to every tab render function."""

    loaded: LoadedArtifacts
    baseline_run: BaselineRun
    temporal_run: TemporalRun
    schema: FeatureSchema
    manifest: SplitManifest
    labelled: list
    samples: list
    dataset_id: str
    reports_dir: Path = field(default_factory=lambda: REPORTS_DIR)


def scenario_ids(count: int) -> list[str]:
    """Scenario ids for a requested count — never silently truncated."""
    if count < 1:
        raise ValueError("at least one scenario is required")
    return [f"scenario-{index:02d}" for index in range(1, count + 1)]


def invalidate_stale_models(fingerprint: str) -> bool:
    """Check if the dataset fingerprint changed and clear stale session state.

    Returns True if the fingerprint was stale (models were invalidated).
    """
    import streamlit as st

    if st.session_state.get("dataset_fingerprint") != fingerprint:
        for stale in ("baseline_run", "temporal_run", "schema", "replay_eval"):
            st.session_state.pop(stale, None)
        st.session_state["dataset_fingerprint"] = fingerprint
        return True
    return False
