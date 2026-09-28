# SPDX-License-Identifier: Apache-2.0
"""Feature-drift monitoring: PSI against a training snapshot, with an honest band.

The Population Stability Index compares a live feature distribution against a
reference (training) snapshot. The statistic is fine. The **bands** were the
problem, and this module used to ship them as constants.

``band_of`` used to call anything above 0.10 "moderate" and above 0.25
"significant". Those are the conventional numbers and they are quoted without the
sample size that produces them, which makes them unfalsifiable. Sprint 8 measured
what they actually mean here: on 400 held-out blocks of iid Gaussian noise - no
drift at all - **100% exceeded 0.10** and 92% exceeded it on a single feature.
So ``band_of`` answered "significant" for ordinary noise, and ``/v1/drift``
inherited that.

The fix is a band that means something: compare the observed PSI against a
threshold calibrated on held-out blocks from the *same* population, and report
where the observation sits in that null distribution. With no null sample there
is nothing to compare against, so **no band is emitted at all** rather than a
decorative one - ``band`` is ``None`` and the response says why.

That is a breaking change to the response, hence ``drift-report-v2``. The old
loader cannot be kept working honestly, because keeping it would mean keeping the
unanchored numbers.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

DRIFT_REPORT_VERSION = "drift-report-v2"
PSI_BINS = 10
EPS = 1e-6

#: Default level for the calibrated trip point. Named so a caller can see it, not
#: to make it authoritative: it means "1 false alarm in 100 held-out blocks".
DEFAULT_NULL_LEVEL = 0.99

WITHIN_NULL = "within_null"
EXCEEDS_NULL = "exceeds_null"

BAND_CAVEAT = (
    "No band is stated because no null sample was supplied, and a fixed PSI "
    "cutoff does not correspond to a false-alarm rate at any particular sample "
    "size. Supply `null`: held-out blocks from the same population as the "
    "reference, and the band becomes a measured statement."
)
BAND_CAVEAT_CALIBRATED = (
    "The band compares this PSI against held-out blocks from the same population "
    "as the reference. It is a statement about that null, not a property of PSI."
)


class DriftReport(BaseModel):
    """PSI for one feature against its reference distribution."""

    model_config = ConfigDict(extra="forbid")

    feature: str = Field(min_length=1)
    psi: float = Field(ge=0.0)
    band: str | None = None
    threshold: float | None = None
    null_percentile: float | None = None
    level: float | None = None
    reference_count: int = Field(ge=0)
    current_count: int = Field(ge=0)
    report_version: str = DRIFT_REPORT_VERSION
    caveat: str = BAND_CAVEAT


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


def null_threshold(
    reference: list[float],
    null_blocks: list[list[float]],
    *,
    level: float = DEFAULT_NULL_LEVEL,
    bins: int = PSI_BINS,
) -> tuple[float, list[float]]:
    """Trip point for this feature, from held-out blocks of the same population.

    Each block is scored independently against ``reference`` and the ``level``
    quantile of the resulting PSIs is the trip point. Passing the *same* sample
    the threshold is later compared against would score blocks against bin edges
    estimated from themselves and report a rate better than the statistic can
    deliver, so ``null_blocks`` must be disjoint from ``reference``.
    """
    if not 0.5 < level < 1.0:
        raise ValueError("level is a quantile of the null and must be in (0.5, 1)")
    if len(null_blocks) < 2:
        raise ValueError("at least two null blocks are required to place a threshold")
    scores = sorted(psi(reference, block, bins=bins) for block in null_blocks)
    index = min(len(scores) - 1, int(round(level * (len(scores) - 1))))
    return scores[index], scores


def band_of(psi_value: float, threshold: float | None) -> str | None:
    """Band against a calibrated threshold, or ``None`` when there is not one.

    ``threshold`` is required and there is deliberately no default. The previous
    signature took a bare PSI and banded it against 0.10 and 0.25, which is how a
    fixed cutoff that means nothing became indistinguishable from a measurement.
    """
    if threshold is None:
        return None
    return EXCEEDS_NULL if psi_value > threshold else WITHIN_NULL


def compare_feature(
    feature: str,
    reference: list[float],
    current: list[float],
    *,
    null_blocks: list[list[float]] | None = None,
    level: float = DEFAULT_NULL_LEVEL,
) -> DriftReport:
    """PSI report for one named feature, banded against a null when one is given.

    Without ``null_blocks`` the report carries the statistic and no band. That is
    the honest state: the caller has a number and not yet a reference for judging
    it.
    """
    value = psi(reference, current)
    if not null_blocks:
        return DriftReport(
            feature=feature,
            psi=value,
            reference_count=len(reference),
            current_count=len(current),
        )
    threshold, scores = null_threshold(reference, null_blocks, level=level)
    percentile = 100.0 * sum(1 for score in scores if score <= value) / len(scores)
    return DriftReport(
        feature=feature,
        psi=value,
        band=band_of(value, threshold),
        threshold=threshold,
        null_percentile=round(percentile, 1),
        level=level,
        reference_count=len(reference),
        current_count=len(current),
        caveat=BAND_CAVEAT_CALIBRATED,
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


__all__ = [
    "DEFAULT_NULL_LEVEL",
    "DRIFT_REPORT_VERSION",
    "EXCEEDS_NULL",
    "WITHIN_NULL",
    "DriftReport",
    "DriftSnapshot",
    "band_of",
    "compare_feature",
    "null_threshold",
    "psi",
]
