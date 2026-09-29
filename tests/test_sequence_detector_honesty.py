# SPDX-License-Identifier: Apache-2.0
"""The transition prior must not manufacture certainty by normalizing on itself.

`predict_next_technique` divided every accumulated score by the **maximum**,
which forces the largest element to exactly 1.0 by construction. Everything
downstream was therefore a constant rather than a gate: `min_probability=0.30`
could never reject a candidate, `is_alert = best_prob >= 0.60` was always true,
and `confidence` was always "high".

Measured before the fix, a two-finding window returned
`{'credential_abuse': 1.0, 'lateral_movement': 0.176}` — the leading 1.0 said
only that it was the larger of the two.

This file also pins what the component is *not*. It is an intra-window
co-occurrence heuristic, not a temporal sequence predictor: `run_all_detectors`
hands it the current window's findings, so it has no cross-window state and
cannot provide lead time. That limitation is documented rather than papered over,
because making it real would mean threading per-scenario detection history
through the window loop, which is a design change.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.detectors import (
    DetectorContext,
    DetectorSet,
    run_all_detectors,
)
from sentinel.schemas import AttackFinding, NetworkState
from sentinel.sequence_detector import (
    ATTACK_TRANSITIONS,
    detect_sequence_prediction,
    predict_next_technique,
)

START = datetime(2026, 1, 1, tzinfo=UTC)


def finding(attack_type: str, *, alert: bool = True, probability: float = 0.9):
    return AttackFinding(
        attack_type=attack_type,
        probability=probability,
        severity="high",
        confidence="high",
        is_alert=alert,
        mitre_technique="T0000",
        affected_assets=[],
        evidence=[],
        warnings=[],
        model_version="test",
    )


def test_the_argmax_is_not_forced_to_one() -> None:
    """The core regression: normalizing on the maximum pinned the winner at 1.0."""
    predictions = predict_next_technique([finding("reconnaissance")])

    assert predictions, "expected a prediction for a known precursor technique"
    best = max(predictions.values())
    assert best < 1.0, (
        f"argmax is {best}; dividing by the maximum pins it at 1.0 regardless of the "
        "transition table"
    )


def test_a_single_observation_returns_the_raw_transition_probability() -> None:
    """With one technique observed, the score should be that row of the table.

    This also pins the second bug: `total_weight` was incremented once per
    successor, so reconnaissance's 0.85 surfaced as 0.425.
    """
    predictions = predict_next_technique([finding("reconnaissance")])
    row = ATTACK_TRANSITIONS["reconnaissance"]

    for technique, value in predictions.items():
        assert value == pytest.approx(row[technique], abs=1e-9), (
            f"{technique} scored {value} but the table says {row[technique]}"
        )
    assert sum(predictions.values()) == pytest.approx(1.0, abs=1e-9), (
        "the scores must form a distribution over the successor techniques"
    )


def test_min_probability_can_actually_reject_a_candidate() -> None:
    """Before the fix `min_probability` was unreachable, because every argmax was 1.0.

    The gate is now live: a threshold above the table's strongest transition
    returns None instead of a finding.
    """
    strong = detect_sequence_prediction([finding("reconnaissance")] * 2, min_probability=0.30)
    rejected = detect_sequence_prediction([finding("reconnaissance")] * 2, min_probability=0.99)

    assert strong is not None, "a 0.85 transition must clear a 0.30 gate"
    assert rejected is None, (
        "a 0.85 transition produced a finding despite min_probability=0.99; the gate is "
        "not being applied"
    )


def test_the_alert_bar_tracks_the_probability_rather_than_being_constant() -> None:
    """`is_alert` used to be a constant True for any candidate that survived.

    The bar is 0.60, so a technique whose strongest transition is below it must
    not alert and one above it must.
    """
    strong = detect_sequence_prediction([finding("reconnaissance")] * 2)
    assert strong is not None
    assert strong.probability == pytest.approx(0.85)
    assert strong.is_alert, "0.85 is above the 0.60 bar and must alert"

    weak = detect_sequence_prediction([finding("lateral_movement")] * 2, min_probability=0.0)
    assert weak is not None, "lateral_movement has a transition row, so it must predict"
    assert weak.probability == pytest.approx(0.50), (
        "lateral_movement's strongest transition is command_and_control at 0.50"
    )
    assert not weak.is_alert, (
        f"a {weak.probability} transition alerted; the bar is 0.60 and is_alert is not a constant"
    )
    assert weak.confidence == "medium", (
        "0.50 maps to medium on the 0.40/0.65 bands; it is no longer pinned to high"
    )


def test_it_is_not_a_temporal_sequence_detector() -> None:
    """Document the real behaviour: the caller supplies one window's findings.

    `run_all_detectors` passes `recent_alerts = [f for f in findings if
    f.is_alert]` where `findings` came from `ctx.state` alone. There is no
    cross-window state, so ordering across windows cannot influence the result
    and the component cannot provide lead time.
    """
    import inspect

    import sentinel.detectors as detectors

    source = inspect.getsource(detectors.run_all_detectors)
    assert "recent_alerts = [f for f in findings if f.is_alert]" in source, (
        "the caller shape changed; re-evaluate whether this is still an "
        "intra-window heuristic and update this test to match"
    )
    # No per-scenario detection history is threaded through the window loop.
    assert "sequence_history" not in source
    assert "detection_history" not in source


def test_the_finding_is_labelled_as_a_prediction_not_an_observation() -> None:
    result = detect_sequence_prediction(
        [finding("reconnaissance"), finding("lateral_movement")], min_probability=0.0
    )
    assert result is not None
    assert result.mitre_technique == "sequence-prediction", (
        "the discriminator that keeps this out of detector benchmark buckets"
    )
    assert any("Sequence prediction" in w for w in result.warnings)


def test_no_single_observation_can_alert_on_its_own() -> None:
    """`len(recent_findings) < 2` returns None, so one finding never predicts."""
    assert detect_sequence_prediction([finding("reconnaissance")]) is None


def test_the_transition_table_is_labelled_as_a_prior() -> None:
    """The old comment claimed MITRE-derived statistics with no citation."""
    import sentinel.sequence_detector as sd

    source = sd.__file__ or ""
    assert source.endswith("sequence_detector.py")
    text = open(source, encoding="utf-8").read()
    assert "authored prior" in text, (
        "the table must state that ATTACK_TRANSITIONS is authored, not measured"
    )
    assert "Derived from MITRE ATT&CK defender-oriented statistics" not in text, (
        "the unsourced provenance claim is back"
    )


def test_the_component_does_not_alert_on_a_quiet_window() -> None:
    """End-to-end: a window that trips nothing must produce no prediction."""
    state = NetworkState(
        window_start=START,
        window_end=START + timedelta(seconds=60),
        features={"bytes": 1000.0, "event_count": 4.0, "flow_event_count": 4.0},
    )
    findings = run_all_detectors(state, ())
    predictions = [f for f in findings if f.mitre_technique == "sequence-prediction"]
    assert not predictions, f"quiet window produced {predictions}"
    assert not any(f.is_alert for f in findings)
    assert DetectorContext(state=state) is not None
    assert DetectorSet().recon == 0.80
