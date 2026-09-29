# SPDX-License-Identifier: Apache-2.0
"""Derived-window export must round-trip without quietly changing the data.

The whole point of committing a pre-windowed dataset is that a judge sees the
same numbers the benchmark published. That only holds if save/load is lossless
for the columns the model reads. A silent drop here - a feature name, a label, a
scenario - would make the shipped artefact disagree with every report in
``docs/RESULTS.md`` while still looking healthy.
"""

from __future__ import annotations

import pytest

from sentinel.derived import (
    DERIVED_VERSION,
    FEATURE_PREFIX,
    DerivedMeta,
    load_derived_meta,
    load_derived_windows,
    save_derived_windows,
)
from sentinel.schemas import NetworkState, StateLabel
from sentinel.targets import LabelledState

CITATION = "Sharafaldin, Lashkari & Ghorbani, ICISSP 2018"


def _labelled(n: int = 6) -> list[LabelledState]:
    out = []
    for i in range(n):
        stage = "Benign" if i % 2 == 0 else "Lateral Movement"
        state = NetworkState(
            window_start=f"2017-07-04T08:{i:02d}:00Z",
            window_end=f"2017-07-04T08:{i:02d}:30Z",
            features={"bytes": float(100 * (i + 1)), "syn_ratio": 0.25 * i},
            entities=["a", "b"],
        )
        out.append(
            LabelledState(
                state_key=f"k{i}",
                scenario_id="tuesday-am" if i < 3 else "tuesday-pm",
                state=state,
                label=StateLabel(
                    state_key=f"k{i}",
                    scenario_id="tuesday-am" if i < 3 else "tuesday-pm",
                    infiltration=stage != "Benign",
                    attack_stage=stage,
                    label_source="dataset",
                ),
            )
        )
    return out


def test_round_trip_preserves_features_labels_and_scenarios(tmp_path):
    out = save_derived_windows(
        tmp_path / "d.parquet",
        _labelled(),
        dataset_id="test",
        source="unit test",
        window_seconds=60,
        stride_seconds=30,
        citation=CITATION,
    )
    loaded, meta = load_derived_windows(out)

    assert meta.derived_version == DERIVED_VERSION
    assert len(loaded) == 6
    for original, restored in zip(_labelled(), loaded, strict=True):
        assert restored.scenario_id == original.scenario_id
        assert restored.state_key == original.state_key
        assert restored.label.attack_stage == original.label.attack_stage
        assert restored.label.infiltration == original.label.infiltration
        assert restored.state.features == original.state.features
        assert restored.state.window_start == original.state.window_start


def test_sidecar_records_citation_and_stage_counts(tmp_path):
    out = save_derived_windows(
        tmp_path / "d.parquet",
        _labelled(),
        dataset_id="test",
        source="unit test",
        window_seconds=60,
        stride_seconds=30,
        citation=CITATION,
    )
    meta = load_derived_meta(out)
    assert meta.citation == CITATION
    assert meta.windows == 6
    assert sum(meta.stages.values()) == 6
    assert meta.stages["Benign"] == 3
    assert FEATURE_PREFIX + "bytes" in meta.feature_names or "bytes" in meta.feature_names


def test_missing_sidecar_is_an_error_not_a_silent_empty_read(tmp_path):
    out = save_derived_windows(
        tmp_path / "d.parquet",
        _labelled(),
        dataset_id="test",
        source="unit test",
        window_seconds=60,
        stride_seconds=30,
        citation=CITATION,
    )
    out.with_suffix(".meta.json").unlink()
    with pytest.raises(FileNotFoundError):
        load_derived_windows(out)


def test_zero_windows_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="zero windows"):
        save_derived_windows(
            tmp_path / "d.parquet",
            [],
            dataset_id="test",
            source="unit test",
            window_seconds=60,
            stride_seconds=30,
            citation=CITATION,
        )


def test_meta_forbids_unknown_fields():
    """Version bumps that add columns must be a deliberate, reviewed change."""
    with pytest.raises(ValueError):
        DerivedMeta.model_validate(
            {
                "dataset_id": "x",
                "source": "y",
                "window_seconds": 60,
                "stride_seconds": 30,
                "windows": 1,
                "feature_names": [],
                "stages": {},
                "generated_at": "2026-01-01T00:00:00+00:00",
                "citation": CITATION,
                "unexpected": 1,
            }
        )
