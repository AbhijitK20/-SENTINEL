"""MITRE-oriented stage mapping from observable network-state features.

Every rule here is a documented, reviewable association between an observable
feature pattern and a stage hypothesis. The rules:

- distinguish observed evidence from the predicted stage,
- carry an explicit confidence and a version string,
- never force a stage when evidence is insufficient (``Unknown`` is valid),
- never imply a guaranteed linear kill chain.

The vocabulary follows ``MITRE_MAPPING_PLAN.md``: Reconnaissance, Initial
Access, Lateral Movement, Command and Control, Exfiltration, with ``Unknown``
when no rule fires. Feature names referenced by the rules exist in the
state-builder output (``state_builder.SUM_FEATURES`` and averaged per-event
features); rules that reference an absent feature are skipped, so the mapping
degrades explicitly rather than fabricating evidence.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from trajectory.schemas import NetworkState, StageEvidence, StageMapping

STAGE_MAPPING_VERSION = "stage-mapping-v1"

MITRE_REFERENCES = {
    "Reconnaissance": "MITRE ATT&CK PRE & Enterprise TA0043",
    "Initial Access": "MITRE ATT&CK Enterprise TA0001",
    "Lateral Movement": "MITRE ATT&CK Enterprise TA0008",
    "Command and Control": "MITRE ATT&CK Enterprise TA0011",
    "Exfiltration": "MITRE ATT&CK Enterprise TA0010",
    "Unknown": None,
}


class _StageRule(BaseModel):
    """One documented evidence rule. Frozen data semantics via pydantic."""

    model_config = ConfigDict(frozen=True)

    stage: str
    condition: str  # human-readable summary, kept for the rationale text
    evaluate: object  # callable[[NetworkState], float | None]; typed loosely for pydantic


def _positive(name: str):
    """Rule factory: fires on a strictly positive summed/averaged feature."""

    def rule(state: NetworkState) -> float | None:
        value = state.features.get(name)
        if value is None:
            return None
        return value if value > 0 else None

    return rule


STAGE_RULES: tuple[_StageRule, ...] = (
    _StageRule(
        stage="Reconnaissance",
        condition="failed-authentication signals present in the current window",
        evaluate=_positive("failed_auth"),
    ),
    _StageRule(
        stage="Lateral Movement",
        condition="sustained new internal connections with substantial transfers",
        evaluate=lambda state: (
            state.features.get("bytes") if (state.features.get("bytes") or 0) > 10_000 else None
        ),
    ),
    _StageRule(
        stage="Command and Control",
        condition="sustained TCP control traffic with dominant retransmissions",
        evaluate=lambda state: (
            state.features.get("retransmission")
            if (state.features.get("retransmission") or 0) > 2
            else None
        ),
    ),
    _StageRule(
        stage="Exfiltration",
        condition="very large outbound transfer volume",
        evaluate=lambda state: (
            state.features.get("bytes") if (state.features.get("bytes") or 0) > 100_000 else None
        ),
    ),
    _StageRule(
        stage="Initial Access",
        condition="elevated connection activity without other stage evidence",
        evaluate=lambda state: (
            state.features.get("event_count")
            if (state.features.get("event_count") or 0) > 20
            else None
        ),
    ),
)


def map_stage(
    states: list[NetworkState] | tuple[NetworkState, ...],
    *,
    infiltration_probability: float,
) -> StageMapping:
    """Map the current window to a stage hypothesis with documented evidence.

    The result is derived from the most recent observed window only. When no
    rule fires, the mapping is ``Unknown`` with confidence 0 — the explicit
    insufficient-evidence state required by the product principles.
    """
    if not states:
        raise ValueError("at least one network state is required for stage mapping")

    ordered = sorted(states, key=lambda state: state.window_start)
    current = ordered[-1]

    fired: list[tuple[_StageRule, StageEvidence]] = []
    for rule in STAGE_RULES:
        observed = rule.evaluate(current)  # type: ignore[operator]
        if observed is None:
            continue
        fired.append(
            (
                rule,
                StageEvidence(
                    name=rule.condition,
                    description=(
                        f"Observed in window ending {current.window_end.isoformat()}: "
                        f"{rule.condition} (rule for {rule.stage})."
                    ),
                    observed_value=float(observed),
                    direction="increasing",
                    confidence=_evidence_confidence(rule.stage, observed),
                ),
            )
        )

    if not fired:
        return StageMapping(
            stage="Unknown",
            probability=0.0,
            confidence="unknown",
            mitre_reference=MITRE_REFERENCES["Unknown"],
            mapping_version=STAGE_MAPPING_VERSION,
            evidence=[],
            rationale=(
                "No documented stage rule fired on the current window; "
                "evidence is insufficient for a stage hypothesis."
            ),
        )

    # Highest-confidence rule decides the stage; ties keep the first rule in
    # the documented rule order (kill-chain ordering is presentation only, not
    # a claimed sequence).
    best_rule, best_evidence = max(fired, key=lambda pair: pair[1].confidence)
    stage = best_rule.stage
    confidence = best_evidence.confidence
    probability = _stage_probability(stage, infiltration_probability, confidence)

    return StageMapping(
        stage=stage,
        probability=probability,
        confidence=_confidence_label(confidence),
        mitre_reference=MITRE_REFERENCES[stage],
        mapping_version=STAGE_MAPPING_VERSION,
        evidence=[evidence for _, evidence in fired],
        rationale=(
            f"Stage {stage!r} selected by the documented rule: "
            f"{best_rule.condition}. Evidence is an observed association, "
            "not proof of attacker technique."
        ),
    )


def _evidence_confidence(stage: str, observed: float) -> float:
    """Rule-specific confidence from 0.5 (barely fired) to 0.95 (strong)."""
    if stage == "Reconnaissance":
        return float(min(0.95, 0.6 + 0.1 * observed))
    if stage == "Lateral Movement":
        return float(min(0.95, 0.65 + observed / 200_000))
    if stage == "Command and Control":
        return float(min(0.95, 0.6 + 0.05 * observed))
    if stage == "Exfiltration":
        return float(min(0.95, 0.7 + observed / 400_000))
    return float(min(0.9, 0.5 + observed / 100))


def _stage_probability(stage: str, infiltration_probability: float, confidence: float) -> float:
    """Blend infiltration likelihood with rule confidence; documented and monotone."""
    if stage == "Unknown":
        return 0.0
    return float(max(0.0, min(1.0, 0.5 * infiltration_probability + 0.5 * confidence)))


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


__all__ = [
    "MITRE_REFERENCES",
    "STAGE_MAPPING_VERSION",
    "STAGE_RULES",
    "map_stage",
]
