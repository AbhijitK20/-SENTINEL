"""Tests for the documented MITRE-oriented stage mapping."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from trajectory.schemas import NetworkState
from trajectory.stage_mapping import (
    STAGE_MAPPING_VERSION,
    map_stage,
)


def _state(features: dict[str, float]) -> NetworkState:
    return NetworkState(
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        features=features,
        entities=["host-01", "auth-service"],
        coverage={"flow": True, "packet": False},
    )


def test_reconnaissance_rule_fires_on_failed_auth() -> None:
    mapping = map_stage(
        [_state({"failed_auth": 3.0, "bytes": 500.0})],
        infiltration_probability=0.2,
    )
    assert mapping.stage == "Reconnaissance"
    assert mapping.mitre_reference is not None
    assert mapping.mapping_version == STAGE_MAPPING_VERSION
    assert mapping.evidence, "firing rule must attach evidence"


def test_lateral_movement_rule_fires_on_large_transfers() -> None:
    mapping = map_stage(
        [_state({"bytes": 50_000.0, "event_count": 30.0})],
        infiltration_probability=0.9,
    )
    assert mapping.stage == "Lateral Movement"


def test_no_evidence_yields_explicit_unknown() -> None:
    mapping = map_stage(
        [_state({"bytes": 100.0, "event_count": 5.0})],
        infiltration_probability=0.9,
    )
    assert mapping.stage == "Unknown"
    assert mapping.probability == 0.0
    assert mapping.confidence == "unknown"
    assert mapping.evidence == []
    assert "insufficient" in mapping.rationale.lower()


def test_empty_states_rejected() -> None:
    with pytest.raises(ValueError, match="at least one network state"):
        map_stage([], infiltration_probability=0.5)


def test_missing_features_degrade_without_fabrication() -> None:
    # A state with none of the rule features must map to Unknown, not guess.
    mapping = map_stage([_state({})], infiltration_probability=0.5)
    assert mapping.stage == "Unknown"


def test_stage_probability_is_blended_and_bounded() -> None:
    mapping = map_stage(
        [_state({"failed_auth": 3.0})],
        infiltration_probability=1.0,
    )
    assert 0.0 <= mapping.probability <= 1.0


def test_states_are_ordered_by_window_start() -> None:
    late = _state({"failed_auth": 3.0})
    early = _state({"bytes": 100.0})
    late.window_start = datetime(2026, 1, 2, tzinfo=UTC)
    late.window_end = datetime(2026, 1, 2, 0, 1, tzinfo=UTC)
    mapping = map_stage([late, early], infiltration_probability=0.5)
    # The most recent window (late) drives the mapping.
    assert mapping.stage == "Reconnaissance"
