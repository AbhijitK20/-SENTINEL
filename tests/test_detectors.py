"""Attack-type detector validation against synthetic ground truth."""

from __future__ import annotations

import pytest

from sentinel.detectors import (
    DetectorContext,
    DetectorSet,
    detect_c2_beacon,
    detect_credential,
    detect_ddos,
    detect_entropy_anomaly,
    detect_exfil,
    detect_lateral,
    detect_recon,
    run_all_detectors,
    severity_from_probability,
)
from sentinel.schemas import NetworkState
from sentinel.targets import LabelledState

SCENARIOS = [f"det{i}" for i in range(4)]


@pytest.fixture(scope="module")
def labelled() -> list[LabelledState]:
    from sentinel.synthetic import generate_labelled_states

    return generate_labelled_states(SCENARIOS, seed=17, window_seconds=60, stride_seconds=30)


def _run(labelled_state: LabelledState, history: list[LabelledState]):
    return run_all_detectors(
        labelled_state.state,
        tuple(item.state for item in history),
    )


def test_benign_windows_stay_quiet(labelled) -> None:
    """Benign windows WITHOUT precursor activity must not alert.

    v2 generator mixes precursor signals (low-rate probing) into the last
    minutes of the benign phase; those windows fire the recon detector by
    design — they are detectable before the formal recon label starts.
    Only early benign windows (no precursor) must stay completely quiet.

    Precursor windows are identified by having more than 5 edges (normal
    benign traffic has 3-4 edges from regular client→server flows).
    """
    for item in labelled:
        if item.label.attack_stage != "Benign":
            continue
        edge_count = len(item.state.edge_summary)
        if edge_count > 5:
            # Precursor signals present — alert is expected
            continue
        findings = run_all_detectors(item.state, ())
        alerting = [f.attack_type for f in findings if f.is_alert]
        assert alerting == [], f"false positives on early benign window: {alerting}"


def test_recon_fires_on_recon_stage_windows(labelled) -> None:
    hits = 0
    recon_windows = 0
    for index, item in enumerate(labelled):
        if item.label.attack_stage != "Reconnaissance":
            continue
        recon_windows += 1
        history = [x.state for x in labelled[max(0, index - 6) : index]]
        finding = detect_recon(_ctx(item.state, history), DetectorSet())
        if finding.is_alert:
            hits += 1
    assert recon_windows > 0
    assert hits / recon_windows >= 0.5, f"recon hits {hits}/{recon_windows} too low"


def test_credential_fires_on_recon_stage_windows(labelled) -> None:
    """Recon phase carries the failed-auth pressure (fa mean 0.13, max 0.25)."""
    hits = 0
    for index, item in enumerate(labelled):
        if item.label.attack_stage != "Reconnaissance":
            continue
        history = [x.state for x in labelled[max(0, index - 6) : index]]
        finding = detect_credential(_ctx(item.state, history), DetectorSet())
        if finding.is_alert:
            hits += 1
    assert hits >= 3, f"credential detector too quiet: {hits}"


def test_lateral_fires_mostly_on_lateral_windows(labelled) -> None:
    """The rule is no longer precision-1.0, and that is the trade that was made.

    This test used to assert that the lateral rule *never* fired outside the
    lateral stage. That was true of the old rule, which scored bytes on *new*
    internal edges: it was precise and nearly blind, seeing 5 of 27 lateral
    windows. The rule now scores bytes on *known* internal edges, because recon
    pre-registers the edges lateral movement later uses and "new" measured the
    wrong quantity. It sees 26 of 27 and misses precision on 2 windows.

    The floors below are the measured behaviour with headroom, not the measured
    values, so a small seed-to-seed wobble does not fail the suite. The exact
    figures come from `make bench-detectors`, which scores a held-out test split
    rather than the training windows this fixture is built from.
    """
    lateral_total = sum(1 for i in labelled if i.label.attack_stage == "Lateral Movement")
    true_positive = false_positive = 0
    for index, item in enumerate(labelled):
        history = [x.state for x in labelled[max(0, index - 6) : index]]
        finding = detect_lateral(_ctx(item.state, history), DetectorSet())
        if not finding.is_alert:
            continue
        if item.label.attack_stage == "Lateral Movement":
            true_positive += 1
        else:
            false_positive += 1
    assert lateral_total > 0
    recall = true_positive / lateral_total
    precision = true_positive / max(1, true_positive + false_positive)
    assert recall >= 0.80, f"lateral recall {recall:.2f} too low"
    assert precision >= 0.70, f"lateral precision {precision:.2f} too low"


def test_lateral_scores_known_edges_not_new_ones(labelled) -> None:
    """The premise, pinned so it cannot be silently reverted.

    The old rule keyed on edges *unseen* in the lookback. Reconnaissance probes
    pre-register the internal edges lateral movement later uses, so during a lateral
    phase most internal edges are already known - the quantity the old rule scored
    moved the wrong way, and a share-based replacement was worse still (F1 0.123
    against 0.312). Volume on known edges is what separates the classes.
    """
    history = [x.state for x in labelled[:6]]
    ctx = _ctx(labelled[6].state, history)
    finding = detect_lateral(ctx, DetectorSet())
    names = {item.name for item in finding.evidence}
    assert "known_edge_bytes" in names
    assert "known_internal_edges" in names
    assert "new_edge_bytes" not in names, "the old, backwards quantity is back"


def test_exfil_alerts_only_on_attack_windows(labelled) -> None:
    for index, item in enumerate(labelled):
        if item.label.attack_stage != "Benign":
            continue
        history = [x.state for x in labelled[max(0, index - 6) : index]]
        finding = detect_exfil(_ctx(item.state, history), DetectorSet())
        assert not finding.is_alert, "exfil alert on a benign window"


def test_ddos_and_c2_are_honest_stubs(labelled) -> None:
    item = labelled[0]
    ddos = detect_ddos(_ctx(item.state, ()), DetectorSet())
    assert ddos.probability == 0.0  # no history -> no z-score -> no fabricated score
    c2 = detect_c2_beacon(_ctx(item.state, ()), DetectorSet())
    assert c2.probability == 0.0
    assert not c2.is_alert
    assert c2.warnings, "C2 must state its telemetry gap explicitly"
    assert "DNS" in c2.warnings[0] or "dns" in c2.warnings[0]


def test_entropy_detector_uses_byte_entropy_not_hash_proxy() -> None:
    """Entropy detector should compute byte-size distribution entropy,
    not hash(endpoint) % 100. The hash proxy is process-randomized
    and unrelated to DNS-label Shannon entropy."""
    from datetime import UTC, datetime, timedelta

    from sentinel.schemas import NetworkState

    start = datetime(2026, 1, 1, tzinfo=UTC)
    # Two edges with distinct byte sizes → entropy should reflect actual bytes
    state = NetworkState(
        window_start=start,
        window_end=start + timedelta(seconds=30),
        features={"bytes": 100.0},
        entities=["src", "dst1", "dst2"],
        edge_summary=[
            {"source": "src", "destination": "dst1", "count": 1.0, "bytes": 100.0},
            {"source": "src", "destination": "dst2", "count": 1.0, "bytes": 200.0},
        ],
        coverage={"flow": True},
        source_ids=[],
    )
    finding = detect_entropy_anomaly(_ctx(state, ()), DetectorSet())
    # Byte entropy should be non-zero (two distinct values)
    byte_ev = [e for e in finding.evidence if e.name == "byte_entropy"]
    assert byte_ev, "entropy detector must report byte_entropy"
    assert byte_ev[0].observed_value > 0.0


def test_every_detector_emits_all_contract_fields(labelled) -> None:
    item = labelled[-1]
    findings = run_all_detectors(item.state, ())
    assert len(findings) == 10  # 9 attack-type + 1 entropy anomaly
    for finding in findings:
        assert finding.model_version.startswith("detectors-")
        assert finding.severity in {"info", "low", "medium", "high", "critical"}
        assert finding.confidence in {"low", "medium", "high"}
        assert finding.mitre_technique.startswith("T")
        assert 0.0 <= finding.probability <= 1.0


def test_severity_banding() -> None:
    assert severity_from_probability(0.95) == "critical"
    assert severity_from_probability(0.70) == "high"
    assert severity_from_probability(0.50) == "medium"
    assert severity_from_probability(0.10) == "low"


def _ctx(state, history):
    return DetectorContext(state=state, history=tuple(history))


# ── real-traffic calibration, measured on CIC-IDS2017 ────────────────────
#
# The low-byte edge share was once a scored term in detect_recon. On the
# synthetic corpus it separated. On real traffic it does not: 698 real benign
# windows sit at a median share of 0.493 and 285 real attack windows at 0.500,
# with the distributions almost fully overlapping, so the old 0.10/0.30 band
# placed 692 of 698 real benign windows above its alert level and
# reconnaissance fired on 981 of 983 real windows.
#
# These tests pin the corrected behaviour. The measured distributions live in
# research/ATTACK_DETECTION_REAL_DATA.md; the numbers below are the ones that
# broke it.


def _realistic_benign_state(rst_count: float = 0.0, low_byte_edges: int = 700):
    """A benign window shaped like real traffic: many tiny edges, no RST storm.

    Real benign windows carry a median of 748 edges at a median low-byte share
    of 0.493, and a median RST probe share of 0.000. That combination is what
    made the old band fire on everything.
    """
    from datetime import UTC, datetime, timedelta

    start = datetime(2017, 7, 4, 9, 0, tzinfo=UTC)
    edges = [
        {
            "source": f"10.0.0.{i % 200}",
            "destination": f"10.0.1.{(i * 7) % 100}",
            "count": 4,
            "bytes": 120.0,  # under PROBE_BYTES: ordinary control traffic
        }
        for i in range(low_byte_edges)
    ]
    return NetworkState(
        window_start=start,
        window_end=start + timedelta(seconds=300),
        features={
            "flow_event_count": 900.0,
            "rst_count": rst_count,
            "bytes": 25_000_000.0,
        },
        entities=[],
        edge_summary=edges,
        coverage={"flow": True, "packet": False},
        source_ids=[],
    )


def test_recon_does_not_score_the_low_byte_edge_share() -> None:
    """The share is evidence, not a signal: real benign traffic is 0.493 of it."""
    from sentinel.detectors import PROBE_BYTES, _probe_score

    state = _realistic_benign_state()
    share = _probe_score(state)
    assert share > 0.45, "fixture should reproduce the real benign low-byte share"
    assert all(e["bytes"] / e["count"] < PROBE_BYTES for e in state.edge_summary)

    finding = detect_recon(_ctx(state, []), DetectorSet())
    assert finding.probability == 0.0, (
        "a benign window whose edges are mostly low-byte must not score; the "
        "low-byte share is evidence only"
    )
    assert not finding.is_alert

    # The value is still reported, so an analyst can see why it looks probe-like.
    reported = {e.name: e.observed_value for e in finding.evidence}
    assert "low_byte_probes" in reported
    assert round(reported["low_byte_probes"], 3) == round(share, 3)


def test_recon_still_scores_a_genuine_rst_storm() -> None:
    """Removing the share must not remove the rule that does discriminate."""
    state = _realistic_benign_state(rst_count=400.0, low_byte_edges=700)
    assert state.features["rst_count"] / state.features["flow_event_count"] > 0.30

    finding = detect_recon(_ctx(state, []), DetectorSet())
    assert finding.probability == 1.0
    assert finding.is_alert


def test_lateral_band_is_a_rate_so_window_length_does_not_change_the_score() -> None:
    """A longer window carries more bytes; the score must not follow it."""
    from datetime import UTC, datetime, timedelta

    from sentinel.evasion import _known_edge_bytes

    edges = [{"source": "10.0.0.1", "destination": "10.0.0.2", "count": 10, "bytes": 20_000.0}]
    history = tuple(
        NetworkState(
            window_start=datetime(2017, 7, 4, 9, 0, tzinfo=UTC) + timedelta(seconds=30 * i),
            window_end=datetime(2017, 7, 4, 9, 0, tzinfo=UTC) + timedelta(seconds=30 * (i + 1)),
            features={},
            entities=[],
            edge_summary=edges,
            coverage={"flow": True, "packet": False},
            source_ids=[],
        )
        for i in range(4)
    )
    scores = []
    for seconds in (30, 300):
        start = datetime(2017, 7, 4, 9, 0, tzinfo=UTC)
        state = NetworkState(
            window_start=start,
            window_end=start + timedelta(seconds=seconds),
            features={},
            entities=[],
            # ten times the bytes, because the window is ten times as long
            edge_summary=[
                {
                    "source": "10.0.0.1",
                    "destination": "10.0.0.2",
                    "count": 10,
                    "bytes": 20_000.0 * (seconds / 30),
                }
            ],
            coverage={"flow": True, "packet": False},
            source_ids=[],
        )
        scores.append(detect_lateral(_ctx(state, list(history)), DetectorSet()).probability)
    assert scores[0] == scores[1], (
        f"identical traffic at two window lengths scored {scores}; the band must be a rate"
    )
    assert _known_edge_bytes is not None
