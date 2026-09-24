"""Tests for incident correlation, risk fusion, and analyst feedback."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinel.assets import default_asset_registry, fuse_risk, risk_level
from sentinel.correlation import correlate, recommend
from sentinel.feedback import FeedbackStore
from sentinel.schemas import AttackFinding

START = datetime(2026, 1, 1, tzinfo=UTC)
REGISTRY = default_asset_registry()


def _finding(
    attack_type: str,
    probability: float,
    *,
    offset: float = 0.0,
    assets: list[str] | None = None,
) -> AttackFinding:
    return AttackFinding(
        attack_type=attack_type,  # type: ignore[arg-type]
        probability=probability,
        severity="high" if probability >= 0.65 else "medium",
        confidence="high" if probability >= 0.85 else "medium",
        is_alert=probability >= 0.8,
        window_start=START + timedelta(seconds=offset),
        window_end=START + timedelta(seconds=offset + 30),
        mitre_technique="T1046",
        affected_assets=assets or [],
        evidence=[],
        warnings=[],
        model_version="detectors-v1",
    )


def test_chained_alerts_form_one_incident_with_progression() -> None:
    findings = (
        _finding("reconnaissance", 0.9, offset=0),
        _finding("credential_abuse", 0.95, offset=60, assets=["auth-service"]),
        _finding("lateral_movement", 0.9, offset=120, assets=["server-03"]),
    )
    incidents = correlate(findings, registry=REGISTRY)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.progression == [
        "Reconnaissance",
        "Credential Abuse",
        "Lateral Movement",
    ]
    assert incident.affected_assets == ["auth-service", "server-03"]
    assert incident.risk.level == "critical"
    assert incident.first_seen == START
    assert incident.last_seen == START + timedelta(seconds=150)


def test_isolated_alerts_become_single_type_incidents() -> None:
    findings = (
        _finding("reconnaissance", 0.9, offset=0),
        _finding("reconnaissance", 0.9, offset=600),  # beyond chain gap
    )
    incidents = correlate(findings)
    assert len(incidents) == 2
    assert all(len(i.finding_attack_types) == 1 for i in incidents)


def test_non_alerting_findings_never_correlate() -> None:
    findings = (_finding("reconnaissance", 0.5, offset=0),)
    assert correlate(findings) == ()


def test_recommendations_are_deduped_and_ordered() -> None:
    findings = [
        _finding("exfiltration", 0.9),
        _finding("reconnaissance", 0.9),
        _finding("reconnaissance", 0.9),
    ]
    actions = recommend(findings)
    assert actions[0].startswith("Review firewall")
    assert actions[-1].startswith("Preserve evidence")
    assert len(actions) == len(set(actions))


def test_fuse_risk_uses_registry_criticality() -> None:
    registered = fuse_risk(0.8, "high", ["server-03"], REGISTRY)
    unregistered = fuse_risk(0.8, "high", ["unknown-host"], REGISTRY)
    assert registered.score > unregistered.score
    assert "neutral criticality" in unregistered.formula
    assert "no registry match" not in registered.formula


def test_risk_level_bands() -> None:
    assert risk_level(0.9) == "critical"
    assert risk_level(0.7) == "high"
    assert risk_level(0.4) == "medium"
    assert risk_level(0.1) == "low"
    assert risk_level(0.0) == "info"


def test_risk_stays_bounded() -> None:
    """Risk must always be in [0,1] regardless of inputs."""
    assert fuse_risk(1.0, "critical", ["server-03"], REGISTRY).score <= 1.0
    assert fuse_risk(0.0, "info", [], None).score >= 0.0
    assert fuse_risk(0.99, "critical", ["server-03"], REGISTRY).score <= 1.0


def test_registered_critical_asset_scores_higher_than_unknown() -> None:
    """Asset criticality contributes to risk; known critical > unknown."""
    reg_critical = fuse_risk(0.8, "high", ["server-03"], REGISTRY)
    reg_high = fuse_risk(0.8, "high", ["file-server"], REGISTRY)
    unknown = fuse_risk(0.8, "high", ["unknown-host"], REGISTRY)
    assert reg_critical.score >= reg_high.score >= unknown.score


def test_attack_technique_alone_does_not_change_risk() -> None:
    """Different MITRE techniques with identical probability/severity/assets
    should produce the same risk. Technique identity is not a risk input."""
    recon = fuse_risk(0.8, "high", ["server-03"], REGISTRY)
    exfil = fuse_risk(0.8, "high", ["server-03"], REGISTRY)
    assert recon.score == exfil.score
    assert recon.level == exfil.level


def test_incident_risk_with_findings() -> None:
    """Incident risk uses the peak finding probability + asset criticality."""
    findings = [
        _finding("reconnaissance", 0.9, offset=0),
        _finding("credential_abuse", 0.95, offset=60, assets=["auth-service"]),
    ]
    incidents = correlate(findings, registry=REGISTRY)
    assert len(incidents) == 1
    assert incidents[0].risk.score > 0.5
    assert incidents[0].risk.level in {"high", "critical"}


def test_incident_risk_formula_includes_only_known_inputs() -> None:
    """Risk formula must reference only probability, asset, and severity.
    No hand-authored EPSS/KEV technique estimates should appear."""
    findings = [_finding("reconnaissance", 0.8, offset=0, assets=["server-03"])]
    incidents = correlate(findings, registry=REGISTRY)
    formula = incidents[0].risk.formula
    assert "EPSS" not in formula
    assert "KEV" not in formula
    assert "prob" in formula or "probability" in formula


def test_feedback_store_records_and_counts(tmp_path) -> None:
    store = FeedbackStore(tmp_path / "feedback.jsonl")
    store.record("INC-001", "true_positive", "analyst-a")
    store.record("INC-001", "false_positive", "analyst-b", comment="benign burst")
    counts = store.verdict_counts()
    assert counts == {"true_positive": 1, "false_positive": 1}
    assert store.false_positive_rate() == 0.5
    assert store.load()[1].comment == "benign burst"
