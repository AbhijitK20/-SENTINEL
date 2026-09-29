# SPDX-License-Identifier: Apache-2.0
"""Pre-windowed dataset export, so a clone can run without the raw capture.

CIC-IDS2017 is 1.2 GB of CSVs behind a licence, and windowing it costs a judge
15-20 minutes and roughly 11 GB of RAM on a laptop that never finishes. The
windowing itself is deterministic and cheap to *reuse*: once 98 features have
been aggregated per window, the result is a few thousand rows.

So this module writes the aggregated windows - not the flows. A window carries
behavioural aggregates (counts, rates, ratios), an attack stage, and a scenario
id. No IP address, port, timestamp-of-flow or raw packet survives, and the
aggregate is a strictly smaller representation than the source. It is committed
so that ``make demo`` shows measured numbers on first paint, with the citation
CIC requires recorded beside it in ``PROVENANCE.md``.

What this is not: it is not a substitute for the raw CSVs when re-fitting, since
the schema statistics are not recoverable from aggregates. Re-training on the
full pipeline still needs the original files.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas import NetworkState, StateLabel
from sentinel.targets import LabelledState

DERIVED_VERSION = "derived-windows-v1"
#: Prefix for feature columns in the parquet, so they cannot collide with the
#: reserved label columns below.
FEATURE_PREFIX = "f_"


class DerivedMeta(BaseModel):
    """Provenance for one derived-window file."""

    model_config = ConfigDict(extra="forbid")

    derived_version: str = DERIVED_VERSION
    dataset_id: str
    source: str
    window_seconds: int = Field(gt=0)
    stride_seconds: int = Field(gt=0)
    windows: int = Field(ge=0)
    feature_names: list[str]
    #: edge_summary is stored as a JSON string column. It is required, not
    #: optional: the detector suite scores known-edge byte rate from it, so a
    #: derived file without edges loads but leaves every detector inert.
    carries_edge_summary: bool = True
    stages: dict[str, int]
    generated_at: str
    citation: str


def save_derived_windows(
    path: str | Path,
    labelled: Sequence[LabelledState],
    *,
    dataset_id: str,
    source: str,
    window_seconds: int,
    stride_seconds: int,
    citation: str,
) -> Path:
    """Write labelled windows to parquet plus a ``.meta.json`` sidecar."""
    import pandas as pd

    if not labelled:
        raise ValueError("cannot export zero windows")

    # Union of features across windows; a window that lacks one carries the
    # schema's missing value rather than NaN leaking into the model.
    names: list[str] = []
    for item in labelled:
        for name in sorted(item.state.features):
            if name not in names:
                names.append(name)
    names.sort()

    rows = []
    stages: dict[str, int] = {}
    for i, item in enumerate(labelled):
        stage = item.label.attack_stage
        stages[stage] = stages.get(stage, 0) + 1
        row = {
            "scenario_id": item.scenario_id,
            "state_key": item.state_key,
            "window_start": item.state.window_start,
            "window_end": item.state.window_end,
            "attack_stage": stage,
            "infiltration": bool(item.label.infiltration),
            "label_source": item.label.label_source,
            "entities": len(item.state.entities),
            "edge_summary": json.dumps(item.state.edge_summary, sort_keys=True),
            "index": i,
        }
        for name in names:
            row[FEATURE_PREFIX + name] = float(item.state.features.get(name, 0.0))
        rows.append(row)

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_parquet(out, index=False)

    meta = DerivedMeta(
        dataset_id=dataset_id,
        source=source,
        window_seconds=window_seconds,
        stride_seconds=stride_seconds,
        windows=len(labelled),
        feature_names=names,
        stages=stages,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        citation=citation,
    )
    out.with_suffix(".meta.json").write_text(json.dumps(meta.model_dump(), indent=2) + "\n")
    return out


def load_derived_meta(path: str | Path) -> DerivedMeta:
    """Read the sidecar describing a derived-window file."""
    meta_path = Path(path).with_suffix(".meta.json")
    if not meta_path.exists():
        raise FileNotFoundError(f"derived windows have no sidecar: {meta_path}")
    return DerivedMeta.model_validate(json.loads(meta_path.read_text()))


def load_derived_windows(path: str | Path) -> tuple[list[LabelledState], DerivedMeta]:
    """Load windows back into the same shape the adapters produce.

    Round-tripping through this is what lets the dashboard, the benchmark and
    the LOEO script consume a derived file without a branch on provenance.
    """
    import pandas as pd

    frame = pd.read_parquet(path)
    meta = load_derived_meta(path)
    names = meta.feature_names

    labelled: list[LabelledState] = []
    for _, row in frame.iterrows():
        features = {
            name: float(row[FEATURE_PREFIX + name])
            for name in names
            if FEATURE_PREFIX + name in row
            and row[FEATURE_PREFIX + name] == row[FEATURE_PREFIX + name]
        }
        state = NetworkState(
            window_start=row["window_start"].to_pydatetime(),
            window_end=row["window_end"].to_pydatetime(),
            features=features,
            entities=[],
            edge_summary=json.loads(row["edge_summary"]) if "edge_summary" in row else [],
            coverage={},
            source_ids=[],
        )
        labelled.append(
            LabelledState(
                state_key=str(row["state_key"]),
                scenario_id=str(row["scenario_id"]),
                state=state,
                label=StateLabel(
                    state_key=str(row["state_key"]),
                    scenario_id=str(row["scenario_id"]),
                    infiltration=bool(row["infiltration"]),
                    attack_stage=str(row["attack_stage"]),
                    label_source=str(row["label_source"]),
                ),
            )
        )
    return labelled, meta
