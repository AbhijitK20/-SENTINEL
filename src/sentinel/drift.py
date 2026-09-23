# SPDX-License-Identifier: Apache-2.0
"""Feature-drift monitoring (roadmap Phase 7): PSI vs a training snapshot.

The Population Stability Index compares live feature distributions against a
reference (training) snapshot. PSI bands are conventional: < 0.1 stable,
0.1-0.25 moderate shift, > 0.25 significant shift. Retraining is deliberately
out of scope; this module's job is to make drift visible and auditable.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

PSI_STABLE = 0.10
PSI_MODERATE = 0.25
PSI_BINS = 10
EPS = 1e-6


class DriftReport(BaseModel):
    """PSI for one feature against its reference distribution."""

    model_config = ConfigDict(extra="forbid")

    feature: str = Field(min_length=1)
    psi: float = Field(ge=0.0)
    band: str
    reference_count: int = Field(ge=0)
    current_count: int = Field(ge=0)


def psi(reference: list[float], current: list[float], *, bins: int = PSI_BINS) -> float:
    """Population Stability Index between two samples over quantile bins.

    Bins come from the reference quantiles; zero counts are floored at EPS so
    the log stays finite (the standard PSI smoothing).
    """
    if not reference or not current:
        return 0.0
    ordered = sorted(reference)
    edges = [
        ordered[min(len(ordered) - 1, int(round((i + 1) * len(ordered) / bins) - 1))]
        for i in range(bins - 1)
    ]

    def counts(values: list[float]) -> list[int]:
        result = [0] * bins
        for value in values:
            index = 0
            for edge in edges:
                if value > edge:
                    index += 1
                else:
                    break
            result[index] += 1
        return result

    ref_counts, cur_counts = counts(ordered), counts(current)
    total = 0.0
    n_ref, n_cur = len(reference), len(current)
    for ref_c, cur_c in zip(ref_counts, cur_counts, strict=True):
        ref_share = max(ref_c / n_ref, EPS)
        cur_share = max(cur_c / n_cur, EPS)
        total += (cur_share - ref_share) * _log(cur_share / ref_share)
    return round(total, 6)


def _log(value: float) -> float:
    import math

    return math.log(value)


def band_of(psi_value: float) -> str:
    if psi_value >= PSI_MODERATE:
        return "significant"
    if psi_value >= PSI_STABLE:
        return "moderate"
    return "stable"


def compare_feature(feature: str, reference: list[float], current: list[float]) -> DriftReport:
    """PSI report for one named feature."""
    value = psi(reference, current)
    return DriftReport(
        feature=feature,
        psi=value,
        band=band_of(value),
        reference_count=len(reference),
        current_count=len(current),
    )


class DriftSnapshot:
    """Reference distributions captured from training states; one JSON doc.

    Dual-mode: set ``db_path`` to persist in SQLite instead of JSONL.
    """

    def __init__(self, path: Path, *, db_path: str | None = None) -> None:
        self.path = path
        self._db = None
        if db_path:
            from sentinel.db import Database

            self._db = Database(db_path)

    def capture(self, states_feature_columns: dict[str, list[float]]) -> None:
        """Persist per-feature reference samples (one JSON document)."""
        doc = json.dumps({k: list(v) for k, v in states_feature_columns.items()})
        if self._db:
            self._db.log_clear("drift_snapshot")
            self._db.log_append("drift_snapshot", doc)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(doc, encoding="utf-8")

    def load(self) -> dict[str, list[float]]:
        if self._db:
            rows = self._db.log_all("drift_snapshot")
            return json.loads(rows[-1]) if rows else {}
        if not self.path.exists():
            return {}
        return {k: list(v) for k, v in json.loads(self.path.read_text(encoding="utf-8")).items()}

    def compare(self, live: dict[str, list[float]]) -> list[DriftReport]:
        """Compare live samples per feature against the captured snapshot."""
        reference = self.load()
        return [
            compare_feature(name, reference[name], values)
            for name, values in sorted(live.items())
            if name in reference and reference[name]
        ]


__all__ = ["DriftReport", "DriftSnapshot", "band_of", "psi"]
