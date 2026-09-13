"""Attack-type detector validation against synthetic ground truth."""

from __future__ import annotations

import pytest

from trajectory.detectors import (
    DetectorContext,
    DetectorSet,
    detect_c2_beacon,
    detect_credential,
    detect_ddos,
    detect_exfil,
    detect_lateral,
    detect_recon,
    run_all_detectors,
    severity_from_probability,
)
from trajectory.targets import LabelledState

SCENARIOS = [f"det{i}" for i in range(4)]


@pytest.fixture(scope="module")
def labelled() -> list[LabelledState]:
    from trajectory.synthetic import generate_labelled_states

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


def test_lateral_fires_only_on_lateral_windows(labelled) -> None:
    fired = 0
    for index, item in enumerate(labelled):
        history = [x.state for x in labelled[max(0, index - 6) : index]]
        finding = detect_lateral(_ctx(item.state, history), DetectorSet())
        if finding.is_alert:
            fired += 1
            assert item.label.attack_stage == "Lateral Movement", (
                f"lateral alert on {item.label.attack_stage}"
            )
    assert fired >= 1, "lateral detector never fires"


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


def test_every_detector_emits_all_contract_fields(labelled) -> None:
    item = labelled[-1]
    findings = run_all_detectors(item.state, ())
    assert len(findings) == 9
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
