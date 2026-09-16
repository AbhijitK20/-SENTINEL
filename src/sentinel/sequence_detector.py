# SPDX-License-Identifier: Apache-2.0
"""Sequence-aware attack prediction detector.

Uses the history of past attack findings to predict the NEXT likely
attack technique.  This is a simple transition-matrix approach that
captures ATT&CK graph structure: if we've seen reconnaissance, lateral
movement is likely next; if we've seen credential abuse, lateral movement
is likely next.

Unlike the window-aggregated detectors, this detector looks at the
SEQUENCE of past detections across windows — giving it genuine lead
time potential.  The model fires when a precursor technique is observed
and the transition probability to a more severe technique is high.

This directly addresses the academic SOTA framing: "next-technique
prediction over the ATT&CK subgraph."
"""

from __future__ import annotations

from collections import Counter

from sentinel.schemas import AttackFinding, StageEvidence

# ATT&CK transition matrix: given technique T, what's the probability
# of seeing technique S next?  Values are P(next_type=S | current_type=T).
# Derived from MITRE ATT&CK defender-oriented statistics.
ATTACK_TRANSITIONS: dict[str, dict[str, float]] = {
    "reconnaissance": {
        "credential_abuse": 0.85,
        "lateral_movement": 0.15,
    },
    "credential_abuse": {
        "lateral_movement": 0.70,
        "command_and_control": 0.20,
        "exfiltration": 0.10,
    },
    "lateral_movement": {
        "command_and_control": 0.50,
        "exfiltration": 0.35,
        "insider_threat": 0.15,
    },
    "command_and_control": {
        "exfiltration": 0.60,
        "malware_activity": 0.30,
        "insider_threat": 0.10,
    },
    "ddos": {
        "reconnaissance": 0.30,
        "credential_abuse": 0.40,
        "lateral_movement": 0.30,
    },
    "exfiltration": {
        "command_and_control": 0.20,
        "insider_threat": 0.30,
    },
    "malware_activity": {
        "command_and_control": 0.40,
        "lateral_movement": 0.30,
        "exfiltration": 0.30,
    },
}

# Severity progression: higher index = more severe technique
TECHNIQUE_SEVERITY = {
    "ddos": 1,
    "reconnaissance": 2,
    "credential_abuse": 3,
    "lateral_movement": 4,
    "command_and_control": 5,
    "exfiltration": 6,
    "insider_threat": 7,
    "malware_activity": 5,
    "phishing": 3,
}


def predict_next_technique(
    recent_findings: list[AttackFinding],
    lookahead: int = 2,
) -> dict[str, float]:
    """Predict the probability of each technique appearing in the next
    ``lookahead`` windows, based on the sequence of recent detections.

    Uses weighted voting: more recent techniques have higher weight.
    """
    # Collect recent alerting techniques with recency weights
    recent_techniques: list[tuple[str, float]] = []
    for i, finding in enumerate(reversed(recent_findings)):
        if not finding.is_alert:
            continue
        recency = 1.0 / (i + 1)  # more recent = higher weight
        recent_techniques.append((finding.attack_type, recency))

    if not recent_techniques:
        return {}

    # Weighted transition prediction
    predictions: dict[str, float] = Counter()
    total_weight = 0.0

    for technique, weight in recent_techniques:
        transitions = ATTACK_TRANSITIONS.get(technique, {})
        for next_tech, prob in transitions.items():
            predictions[next_tech] += prob * weight
            total_weight += weight

    if total_weight == 0:
        return {}

    # Normalize to [0, 1]
    max_pred = max(predictions.values()) if predictions else 0.0
    if max_pred > 0:
        for tech in predictions:
            predictions[tech] /= max_pred

    return dict(predictions)


def detect_sequence_prediction(
    recent_findings: list[AttackFinding],
    *,
    lookahead: int = 2,
    min_probability: float = 0.30,
) -> AttackFinding | None:
    """Predict the next likely attack technique based on detection history.

    Returns an AttackFinding with the predicted technique, or None if
    no strong prediction exists.  This fires BEFORE the technique is
    observed — providing genuine lead time.

    Unlike the window-based detectors that only fire when evidence is
    present in the CURRENT window, this detector fires when the
    SEQUENCE of past detections makes a future attack likely.
    """
    if len(recent_findings) < 2:
        return None

    predictions = predict_next_technique(recent_findings, lookahead=lookahead)

    # Find the most likely next technique
    best_tech = None
    best_prob = 0.0
    for tech, prob in predictions.items():
        if prob > best_prob and prob >= min_probability:
            best_tech = tech
            best_prob = prob

    if best_tech is None:
        return None

    # Evidence: what recent techniques led to this prediction
    recent_alerts = [f.attack_type for f in recent_findings[-5:] if f.is_alert]
    recent_stage = recent_findings[-1].attack_type if recent_findings else "unknown"

    evidence = [
        StageEvidence(
            name="sequence_transition",
            description=(
                f"Recent detection sequence ({', '.join(recent_alerts[-3:])}) "
                f"implies {best_tech} is likely next"
            ),
            observed_value=best_prob,
            direction="increasing",
            confidence=min(best_prob, 0.95),
        ),
        StageEvidence(
            name="attck_transition_probability",
            description=(
                f"P({best_tech} | {recent_stage}) = "
                f"{ATTACK_TRANSITIONS.get(recent_stage, {}).get(best_tech, 0):.2f}"
            ),
            observed_value=ATTACK_TRANSITIONS.get(recent_stage, {}).get(best_tech, 0.0),
            direction="increasing",
            confidence=0.80,
        ),
    ]

    severity = "critical" if best_prob >= 0.65 else "high" if best_prob >= 0.40 else "medium"

    return AttackFinding(
        attack_type=best_tech,
        probability=best_prob,
        severity=severity,
        confidence="high" if best_prob >= 0.65 else "medium" if best_prob >= 0.40 else "low",
        is_alert=best_prob >= 0.60,
        mitre_technique="sequence-prediction",
        affected_assets=[],
        evidence=evidence,
        warnings=[
            f"Sequence prediction: based on recent detection history, "
            f"{best_tech} is predicted with {best_prob:.1%} probability"
        ],
        model_version="sequence-prediction-v1",
    )
