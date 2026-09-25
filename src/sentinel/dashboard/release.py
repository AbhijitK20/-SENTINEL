# SPDX-License-Identifier: Apache-2.0
"""Boot the dashboard from the committed release bundle instead of retraining.

``models/release/<version>`` is checksummed and self-contained; the exporter's
own docstring states that no training is required to run inference. The
dashboard previously ignored it and stopped with "Click Train / Retrain", so
every fresh session retrained the same models.

The bundle stores results, not the training-run wrapper objects the dashboard
consumes, so this module adapts one to the other. Nothing here trains: it only
reads files that are already committed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.predict import load_artifacts

REPO_ROOT = Path(__file__).resolve().parents[3]
RELEASE_DIR = REPO_ROOT / "models" / "release" / "v1"


@dataclass(frozen=True)
class ReleaseBaselineRun:
    """Adapter matching the shape the dashboard expects from ``train_baseline``."""

    result: Any
    model: Any


@dataclass(frozen=True)
class ReleaseTemporalRun:
    """Adapter matching the shape the dashboard expects from ``train_temporal``."""

    result: Any
    models: dict[int, Any]


def release_dataset_id(release_dir: Path = RELEASE_DIR) -> str | None:
    """The dataset the bundle records, or None when it does not say.

    The v1 bundle predates this field, so it returns None and the UI says so
    rather than guessing which dataset produced the shipped weights.
    """
    manifest_path = release_dir / "MANIFEST.json"
    if not manifest_path.is_file():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8")).get("dataset_id")
    except (json.JSONDecodeError, OSError):
        return None


def load_release_runs(
    release_dir: Path = RELEASE_DIR,
) -> tuple[ReleaseBaselineRun, ReleaseTemporalRun, Any] | None:
    """Load the committed bundle as run-shaped objects, or None if unusable."""
    try:
        artifacts = load_artifacts(release_dir, temporal_dir=release_dir)
    except Exception:  # noqa: BLE001 - any unusable bundle falls back to training
        return None
    if artifacts.temporal_result is None:
        return None
    return (
        ReleaseBaselineRun(result=artifacts.baseline_result, model=artifacts.baseline_model),
        ReleaseTemporalRun(result=artifacts.temporal_result, models=artifacts.temporal_models),
        artifacts.baseline_result.feature_schema,
    )
