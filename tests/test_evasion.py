# SPDX-License-Identifier: Apache-2.0
"""Evasion cost: the analysis must not invent vulnerabilities, and must not hide them.

Two failure modes, both tested here:

- **False positives.** A free-form search over 98 feature numbers always finds a
  "cheap" evasion by setting a measured quantity to zero, which describes deleting
  the evidence rather than evading. Every move here is a declared strategy, and
  a move needing exporter tampering is reported as *not* an evasion.
- **False negatives.** Reporting "not evadable" without saying why is useless. A
  rule that never fired has nothing to evade; a rule that fired from the sequence
  detector has an upstream dependency, not a byte-level weakness.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.evasion import (
    EvasionMove,
    RedTeamReport,
    evasion_moves_for,
    red_team,
    render,
)
from sentinel.schemas import AttackFinding, NetworkState

START = datetime(2026, 1, 1, tzinfo=UTC)


def _edge(source: str, destination: str, bytes_: float) -> dict:
    return {"source": source, "destination": destination, "bytes": bytes_}


def _state(offset: int, edges: list[dict]) -> NetworkState:
    start = START + timedelta(minutes=offset)
    return NetworkState(
        window_start=start,
        window_end=start + timedelta(minutes=1),
        features={},
        entities=[],
        edge_summary=edges,
        coverage={"flow": True, "packet": False},
        source_ids=[],
    )


def _finding(attack_type: str, probability: float, alert: bool, technique: str) -> AttackFinding:
    return AttackFinding(
        attack_type=attack_type,
        probability=probability,
        severity="high",
        confidence="medium",
        is_alert=alert,
        mitre_technique=technique,
        model_version="test",
    )


# -- a stubbed detector so the analysis can be tested without the real one ---


def _always_fires(technique: str = "T1046"):
    def run(state, history):
        return [_finding("reconnaissance", 1.0, True, technique)]

    return run


def _never_fires(state, history):
    return [_finding("reconnaissance", 0.1, False, "T1046")]


# ── the cost model ──────────────────────────────────────────────────────


def test_a_move_needing_tampering_is_not_an_evasion() -> None:
    move = EvasionMove(
        detector="ddos",
        name="edit_the_flow_exporter",
        description="suppress the signal in the sensor",
        evades=True,
        requires_exporter_tampering=True,
    )
    assert not move.feasible
    assert not move.is_free


def test_a_free_evasion_is_called_out() -> None:
    move = EvasionMove(
        detector="reconnaissance", name="x", description="", evades=True, cost_bytes=0.0
    )
    assert move.feasible and move.is_free


def test_costs_are_not_collapsed_into_one_number() -> None:
    # Bytes and dwell time are different taxes and are kept separate, because a
    # deployment prices them differently.
    move = EvasionMove(
        detector="lateral_movement",
        name="rehearse",
        description="",
        evades=True,
        cost_bytes=512.0,
        cost_windows=1.0,
    )
    payload = move.as_dict()
    assert payload["cost_bytes"] == 512.0
    assert payload["cost_windows"] == 1.0


def test_a_move_serialises_with_its_verdict() -> None:
    payload = EvasionMove(
        detector="x", name="y", description="z", evades=True, cost_bytes=1.0
    ).as_dict()
    assert payload["evades"] and payload["feasible"]
    assert payload["detector"] == "x"


# ── aiming at the rule that actually fired ──────────────────────────────


def test_a_detector_that_did_not_fire_has_nothing_to_price() -> None:
    state = _state(0, [_edge("a", "b", 10.0)])
    moves = evasion_moves_for("reconnaissance", state, (), _never_fires)
    assert [m.name for m in moves] == ["not_firing"]
    assert not moves[0].evades


def test_a_sequence_derived_alert_is_not_attacked_at_the_byte_level() -> None:
    """The measured case: a lateral alert inferred from detection history.

    Padding bytes on the transfer cannot silence a rule that reads the history,
    and reporting "inevitable" without the reason would be a useless answer.
    """
    state = _state(0, [_edge("a", "b", 80_000.0)])

    def run(current, history):
        return [_finding("lateral_movement", 1.0, True, "sequence-prediction")]

    moves = evasion_moves_for("lateral_movement", state, (), run)
    assert [m.name for m in moves] == ["stay_under_the_upstream_rule"]
    assert "sequence detector" in moves[0].description
    assert not moves[0].evades


def _known_edge_rule(band: float = 50_000.0):
    """A stub of the *current* lateral rule: fires on bytes over known edges.

    The rule used to score bytes over *new* edges, and these tests were written
    against that. Recon pre-registers the edges lateral movement later uses, so
    the premise was backwards; the stub follows the rule, not the other way round.
    """

    def run(current, history_tuple):
        prior = {
            (e["source"], e["destination"]) for w in history_tuple[-5:] for e in w.edge_summary
        }
        known_bytes = sum(
            e["bytes"] for e in current.edge_summary if (e["source"], e["destination"]) in prior
        )
        firing = known_bytes >= band
        return [_finding("lateral_movement", 1.0 if firing else 0.0, firing, "T1021")]

    return run


def test_a_measured_alert_does_get_byte_level_moves() -> None:
    # The transfer is on an edge history already knows, which is what the rule scores.
    state = _state(0, [_edge("a", "b", 80_000.0), _edge("c", "d", 80_000.0)])
    history = (_state(1, [_edge("a", "b", 10.0), _edge("c", "d", 10.0)]),)

    moves = evasion_moves_for("lateral_movement", state, history, _known_edge_rule())
    names = {m.name for m in moves}
    assert "throttle_the_transfer" in names
    assert "split_the_transfer_over_more_edges" in names
    assert "edit_the_flow_exporter" in names


def test_rehearsal_is_not_offered_because_the_rule_no_longer_rewards_it() -> None:
    """Pre-warming defeated the old new-edge rule and now only adds a known edge.

    The move is gone from the enumeration rather than kept and reported as
    failing, because offering an attacker a move that makes them *more* visible
    is noise in a list that is supposed to be short.
    """
    state = _state(0, [_edge("a", "b", 80_000.0)])
    history = (_state(1, [_edge("a", "b", 10.0)]),)
    names = {
        m.name for m in evasion_moves_for("lateral_movement", state, history, _known_edge_rule())
    }
    assert "rehearse_edge_one_window_early" not in names


def test_throttling_is_only_claimed_when_it_actually_stops_the_alert() -> None:
    state = _state(0, [_edge("a", "b", 80_000.0)])
    history = (_state(1, [_edge("a", "b", 10.0)]),)

    moves = {
        m.name: m for m in evasion_moves_for("lateral_movement", state, history, _known_edge_rule())
    }
    # Adding bytes cannot lower a high-byte rule; throttling can, and it costs
    # dwell time rather than bandwidth.
    throttle = moves["throttle_the_transfer"]
    assert throttle.evades
    assert throttle.cost_bytes == 0.0
    assert throttle.cost_windows > 0.0


# ── the report ──────────────────────────────────────────────────────────


def test_red_team_requires_at_least_one_window() -> None:
    with pytest.raises(ValueError, match="at least one window"):
        red_team([], _always_fires())


def test_not_firing_rows_are_collapsed_per_detector() -> None:
    state = _state(0, [_edge("a", "b", 10.0)])
    windows = [(state, ()) for _ in range(5)]
    report = red_team(windows, _never_fires)
    quiet = [m for m in report.moves if m.name == "not_firing"]
    assert len(quiet) == 1, "one row per detector, not one per window"
    assert report.windows_tested == 5


def test_the_report_lists_no_evadable_detector_when_none_are() -> None:
    state = _state(0, [_edge("a", "b", 10.0)])

    def run(current, history_tuple):
        return [_finding("reconnaissance", 1.0, True, "T1046")]

    report = red_team([(state, ())], run)
    assert report.evadable_detectors() == []
    assert report.free_evasions() == []


def test_the_cheapest_evasion_is_chosen_by_dwell_time_then_bytes() -> None:
    cheap_bytes = EvasionMove("d", "a", "", True, cost_bytes=10.0, cost_windows=2.0)
    cheap_time = EvasionMove("d", "b", "", True, cost_bytes=5_000.0, cost_windows=1.0)
    report = RedTeamReport(moves=[cheap_bytes, cheap_time])
    assert report.cheapest_feasible("d") is cheap_time


def test_the_cheapest_evasion_ignores_infeasible_moves() -> None:
    tampered = EvasionMove("d", "a", "", True, requires_exporter_tampering=True, cost_bytes=0.0)
    real = EvasionMove("d", "b", "", True, cost_bytes=9_000.0)
    report = RedTeamReport(moves=[tampered, real])
    assert report.cheapest_feasible("d") is real
    assert report.cheapest_feasible("missing") is None


def test_the_report_serialises_with_its_counts() -> None:
    report = RedTeamReport(
        moves=[EvasionMove("d", "n", "desc", True, cost_bytes=1.0)], windows_tested=3
    )
    payload = report.as_dict()
    assert payload["windows_tested"] == 3
    assert payload["evadable_detectors"] == ["d"]
    assert "version" in payload


def test_the_report_renders_the_honest_headline() -> None:
    report = RedTeamReport(
        moves=[
            EvasionMove(
                "ddos", "edit_the_flow_exporter", "x", True, requires_exporter_tampering=True
            )
        ],
        windows_tested=4,
        detectors_checked=9,
        note="strategies are hand-enumerated",
    )
    text = render(report)
    assert "none of the tested detectors" in text
    assert "hand-enumerated" in text
    assert "hand-enumerated" in text


def test_an_empty_report_still_renders() -> None:
    text = render(RedTeamReport())
    assert "none of the tested detectors" in text
