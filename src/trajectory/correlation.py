"""Incident correlation: group attack findings into analyst-facing cases."""

from __future__ import annotations

from trajectory.assets import fuse_risk
from trajectory.schemas import AttackFinding, Incident, RiskAssessment

CHAIN_GAP_SECONDS = 300.0

PROGRESSION_ORDER = {
    "ddos": 0,
    "reconnaissance": 0,
    "phishing": 0,
    "malware_activity": 1,
    "credential_abuse": 1,
    "insider_threat": 2,
    "lateral_movement": 2,
    "command_and_control": 3,
    "exfiltration": 3,
}

STAGE_NAMES = {
    "reconnaissance": "Reconnaissance",
    "credential_abuse": "Credential Abuse",
    "lateral_movement": "Lateral Movement",
    "exfiltration": "Exfiltration",
    "ddos": "Volumetric Attack",
    "command_and_control": "Command and Control",
    "insider_threat": "Insider Threat",
    "phishing": "Phishing",
    "malware_activity": "Malware Activity",
}

RECOMMENDATIONS = {
    "reconnaissance": "Review firewall logs for the scanning source",
    "credential_abuse": (
        "Check auth logs for targeted accounts; disable suspect accounts pending review"
    ),
    "lateral_movement": ("Isolate affected internal host; restrict SMB/RDP to the targeted server"),
    "exfiltration": "Preserve evidence; review egress logs for the destination",
    "ddos": "Engage upstream scrubbing; rate-limit the targeted service",
    "command_and_control": "Review DNS/proxy logs; hunt the beacon pattern estate-wide",
    "insider_threat": (
        "Review the account's access history with HR; do not confront before evidence is preserved"
    ),
    "phishing": "Search mailboxes and proxy logs for the URL/sender; review click events",
    "malware_activity": "Isolate the endpoint; collect process lineage and file hashes",
}


def fuse_incident_risk(findings: list[AttackFinding], registry) -> RiskAssessment:
    """Risk from the peak finding, +0.05 per additional chained attack type."""
    peak = max(findings, key=lambda f: f.probability)
    assets = sorted({a for f in findings for a in f.affected_assets})
    risk = fuse_risk(peak.probability, peak.severity, assets, registry)
    if len(findings) > 1:
        score = min(1.0, risk.score + 0.05 * (len(findings) - 1))
        from trajectory.assets import risk_level

        return RiskAssessment(
            score=round(score, 3),
            level=risk_level(score),
            formula=risk.formula + " [+0.05 per additional chained attack type]",
        )
    return risk


def recommend(findings: list[AttackFinding]) -> list[str]:
    """Analyst-approved recommendations; the platform never auto-executes."""
    actions: list[str] = []
    types = sorted({f.attack_type for f in findings}, key=PROGRESSION_ORDER.get)
    for attack_type in types:
        action = RECOMMENDATIONS.get(attack_type)
        if action and action not in actions:
            actions.append(action)
    tail = "Preserve evidence; all actions analyst-approved"
    if not any(a.startswith("Preserve evidence") for a in actions):
        actions.append(tail)
    return actions


def correlate(
    findings: tuple[AttackFinding, ...],
    *,
    registry=None,
    incident_id_prefix: str = "INC",
) -> tuple[Incident, ...]:
    """Chain alerting findings into incidents.

    Alerting findings whose windows overlap or sit within CHAIN_GAP_SECONDS
    join one incident; chains are ordered by attack-stage order. Isolated
    alerts become single-type incidents — every alert belongs to a case.
    """
    alerts = sorted(
        (f for f in findings if f.is_alert),
        key=lambda f: (f.window_start, -f.probability),
    )
    if not alerts:
        return ()

    chains: list[list[AttackFinding]] = []
    for finding in alerts:
        if chains and _gap(chains[-1][-1], finding) <= CHAIN_GAP_SECONDS:
            chains[-1].append(finding)
        else:
            chains.append([finding])

    incidents = []
    for index, chain in enumerate(chains, start=1):
        ordered = sorted(chain, key=lambda f: PROGRESSION_ORDER.get(f.attack_type, 99))
        # Progression reads chronologically, one step per attack type — the
        # per-window detail lives in findings, not in the analyst-facing chain.
        seen_types: list[str] = []
        for finding in sorted(chain, key=lambda f: f.window_start):
            if finding.attack_type not in seen_types:
                seen_types.append(finding.attack_type)
        incidents.append(
            Incident(
                incident_id=f"{incident_id_prefix}-{index:03d}",
                risk=fuse_incident_risk(ordered, registry),
                progression=[STAGE_NAMES.get(t, t) for t in seen_types],
                finding_attack_types=sorted(set(f.attack_type for f in ordered)),
                affected_assets=sorted({a for f in ordered for a in f.affected_assets}),
                first_seen=min(f.window_start for f in ordered),
                last_seen=max(f.window_end for f in ordered),
                recommended_actions=recommend(ordered),
            )
        )
    return tuple(incidents)


def _gap(previous: AttackFinding, following: AttackFinding) -> float:
    if following.window_start <= previous.window_end:
        return 0.0
    return (following.window_start - previous.window_end).total_seconds()
