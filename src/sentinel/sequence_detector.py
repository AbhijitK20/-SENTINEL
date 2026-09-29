# SPDX-License-Identifier: Apache-2.0
"""Transition-prior attack prediction over ATT&CK techniques.

**What this is, stated precisely because the old docstring overstated it.** The
previous module docstring claimed this detector "looks at the SEQUENCE of past
detections across windows — giving it genuine lead time" and that it "fires
BEFORE the technique is observed". In the wired path neither was true.
`run_all_detectors` calls it with the alerting findings of the *current* window
(`detectors.py`: `recent_alerts = [f for f in findings if f.is_alert]`, where
`findings` was computed a few lines earlier from `ctx.state` alone). It is
therefore an **intra-window co-occurrence heuristic**: given the techniques that
fired in this window, which technique does the transition table rank highest.
There is no cross-window state, so it has no temporal lead, and the finding it
emits describes a prior rather than an observation.

Making it a real temporal sequence predictor would mean threading per-scenario
detection history through the window loop, which is a design change and outside
the scope of a correctness fix. What was fixed here is the part that was simply
wrong.

**The normalization bug.** `predict_next_technique` accumulated
`predictions[next] += probability * weight` alongside `total_weight += weight`
and then divided every value by the **maximum**:

    max_pred = max(predictions.values())
    predictions[tech] /= max_pred

which forces the largest element to exactly 1.0 by construction. Every caller
downstream is then a no-op or a constant: `min_probability=0.30` can never
reject anything, `is_alert = best_prob >= 0.60` is always true, and `confidence`
is always "high". Measured before the fix, a two-finding window returned
`{'credential_abuse': 1.0, 'lateral_movement': 0.176}` — the first entry is 1.0
purely because it was the larger of the two, not because the transition was
certain.

The function already accumulated the correct denominator and simply never used
it. Dividing by `total_weight` instead restores the intended semantics: with a
single observed technique the result is the raw transition probability, so the
argmax is below 1.0 unless the table actually says so, and the gates above it
start working.
"""

from __future__ import annotations

from collections import Counter

from sentinel.schemas import AttackFinding, StageEvidence

# ATT&CK transition prior: given technique T, the authored likelihood of
# technique S following. Values are P(next_type=S | current_type=T).
#
# **These are authored priors, not measured statistics.** An earlier comment here
# attributed them to MITRE ATT&CK defender statistics while citing nothing; MITRE
# publishes technique relationships, not transition frequencies, so that
# overstated the provenance. A second, disagreeing table lives in
# `threat_enrichment.py` and is labelled there for the same reason. Neither is
# calibrated against telemetry. Treat both as priors, and see
# `threat_enrichment.transition_source()`, which reports which table produced a
# given prediction.
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
    """Score each technique against a recency-weighted transition prior.

    ``lookahead`` is accepted for signature compatibility and is unused: the
    table is a single-step prior.
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

    # Weighted transition prediction.
    predictions: dict[str, float] = Counter()
    total_weight = 0.0

    for technique, weight in recent_techniques:
        # The weight belongs to the observed technique, so it is counted once
        # here. It used to be incremented inside the successor loop, which
        # counted it once per successor: a technique with three successors had
        # its transition probabilities divided by three, so reconnaissance's
        # 0.85 surfaced as 0.425.
        total_weight += weight
        transitions = ATTACK_TRANSITIONS.get(technique, {})
        for next_tech, prob in transitions.items():
            predictions[next_tech] += prob * weight

    if total_weight == 0:
        return {}

    # Normalize by the accumulated weight, not by the maximum. Dividing by the
    # maximum forces the argmax to exactly 1.0, which made every gate above this
    # function a no-op; `total_weight` was accumulated for this purpose and never
    # used. See the module docstring.
    for tech in predictions:
        predictions[tech] /= total_weight

    return dict(predictions)


def detect_sequence_prediction(
    recent_findings: list[AttackFinding],
    *,
    lookahead: int = 2,
    min_probability: float = 0.30,
) -> AttackFinding | None:
    """Predict the next likely attack technique from a transition prior.

    Returns an AttackFinding carrying the highest-ranked technique, or None when
    nothing clears ``min_probability``.

    **This is not a temporal sequence predictor and has no lead time.** The
    callers pass the alerting findings of a single window, so the "sequence"
    being read is which techniques co-occurred in one window, not an ordered
    progression across windows. The returned probability is the authored
    transition prior scaled by the observation weights — it says "given these
    techniques fired together, the table ranks that one highest", not "that one
    is coming next". The module docstring records what a real implementation
    would require.

    ``lookahead`` is accepted for signature compatibility and is not used: the
    table is a single-step prior and the caller decides how many steps to
    imagine.
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
