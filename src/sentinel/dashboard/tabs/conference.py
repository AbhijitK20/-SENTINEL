"""4-Agent Conference — structured debate over the current forecast.

Four agents analyze the same forecast from different perspectives, challenge
each other's claims, and synthesize a final verdict. No LLM required —
each agent applies domain-specific rules to the forecast state.

Agents:
  1. Analyst  — "Here's what the data shows"
  2. Guardian — "Here's what this means for defense"
  3. Skeptic  — "Here's why that analysis might be wrong"
  4. Synthesizer — "Here's the consensus after considering all perspectives"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentClaim:
    agent: str
    role: str
    emoji: str
    statement: str
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    targets: list[str] = field(default_factory=list)


@dataclass
class AgentResponse:
    agent: str
    role: str
    emoji: str
    responds_to: str
    rebuttal: str


@dataclass
class ConferenceResult:
    scenario: str
    window: int
    peak_probability: float
    predicted_stage: str
    confidence: str
    lead_windows: int | None
    stage_rationale: str
    stage_evidence: list[dict[str, Any]]
    top_features: list[tuple[str, float]]
    round1: list[AgentClaim]
    round2: list[AgentResponse]
    round3: dict[str, str]
    verdict: str
    consensus_score: float
    action_items: list[str]


def _top_features(result: Any, history: list[Any], n: int = 5) -> list[tuple[str, float]]:
    """Extract the top driving features from the forecast result."""
    if hasattr(result, "feature_importances") and result.feature_importances:
        items = sorted(result.feature_importances.items(), key=lambda x: abs(x[1]), reverse=True)
        return items[:n]
    window = history[-1] if history else None
    if window is None:
        return []
    features = getattr(window, "features", None)
    if not features:
        return []
    items = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
    return items[:n]


def _asset_count(history: list[Any]) -> int:
    """Count unique entities observed across history."""
    entities: set[str] = set()
    for w in history:
        for e in getattr(w, "entities", []):
            entities.add(e)
    return len(entities)


def _event_trend(history: list[Any]) -> str:
    """Describe whether event counts are increasing, stable, or decreasing."""
    counts = [getattr(w, "event_count", 0) for w in history[-5:]]
    if len(counts) < 2:
        return "insufficient"
    avg_first = sum(counts[: len(counts) // 2]) / max(len(counts) // 2, 1)
    avg_last = sum(counts[len(counts) // 2 :]) / max(len(counts) - len(counts) // 2, 1)
    ratio = avg_last / max(avg_first, 1)
    if ratio > 1.3:
        return "increasing"
    if ratio < 0.7:
        return "decreasing"
    return "stable"


def _bytes_trend(history: list[Any]) -> str:
    """Describe whether bytes are increasing."""
    counts = [getattr(w, "bytes_total", 0) for w in history[-5:]]
    if len(counts) < 2:
        return "insufficient"
    avg_first = sum(counts[: len(counts) // 2]) / max(len(counts) // 2, 1)
    avg_last = sum(counts[len(counts) // 2 :]) / max(len(counts) - len(counts) // 2, 1)
    ratio = avg_last / max(avg_first, 1)
    if ratio > 1.5:
        return "increasing rapidly"
    if ratio > 1.2:
        return "increasing"
    if ratio < 0.8:
        return "decreasing"
    return "stable"


# ── Round 1: Each agent presents its analysis ────────────────────────


def _analyst_round1(
    result: Any, history: list[Any], features: list[tuple[str, float]], assets: int
) -> AgentClaim:
    prob = result.predicted_stage.probability
    stage = result.predicted_stage.name
    conf = result.predicted_stage.confidence
    event_trend = _event_trend(history)
    bytes_trend = _bytes_trend(history)

    if prob >= 0.8:
        assessment = (
            f"The model assigns {prob:.1%} probability to {stage}. "
            f"This is above the 0.80 critical threshold."
        )
    elif prob >= 0.5:
        assessment = (
            f"The model assigns {prob:.1%} probability to {stage}. "
            f"This exceeds the 0.50 alert threshold."
        )
    elif prob >= 0.2:
        assessment = (
            f"The model assigns {prob:.1%} probability to {stage}. "
            f"This is below the alert threshold but above baseline."
        )
    else:
        assessment = (
            f"The model assigns {prob:.1%} probability to {stage}. This is near baseline levels."
        )

    evidence = [
        f"Event count trend: {event_trend} across last 5 windows",
        f"Bytes trend: {bytes_trend}",
        f"Assets observed: {assets}",
        f"Confidence: {conf}",
    ]
    if features:
        top_name, top_val = features[0]
        evidence.append(f"Top feature: {top_name} = {top_val:.3f}")

    return AgentClaim(
        agent="Analyst",
        role="Data Analyst",
        emoji=":",
        statement=assessment,
        evidence=evidence,
        confidence=prob,
        targets=["Skeptic"],
    )


def _guardian_round1(
    result: Any, history: list[Any], features: list[tuple[str, float]], assets: int
) -> AgentClaim:
    prob = result.predicted_stage.probability
    stage = result.predicted_stage.name
    lead = result.lead_time
    lead_windows = lead.lead_windows if lead else None

    if prob >= 0.8 and lead_windows is not None and lead_windows >= 1:
        readiness = "immediate action required"
        msg = (
            f"High probability ({prob:.1%}) with {lead_windows}-window lead time. "
            f"Defensive posture: pre-position containment controls on the {assets} "
            f"observed assets now, before {stage} fully materializes."
        )
    elif prob >= 0.5:
        readiness = "elevated monitoring"
        msg = (
            f"Moderate probability ({prob:.1%}) of {stage}. "
            f"Increase monitoring on the {assets} assets and prepare containment "
            f"playbooks. No immediate action needed but readiness is advised."
        )
    elif prob >= 0.2:
        readiness = "routine monitoring"
        msg = (
            f"Low-to-moderate probability ({prob:.1%}). "
            f"Standard monitoring sufficient. The {assets} assets show no urgent "
            f"exposure requiring intervention."
        )
    else:
        readiness = "no action"
        msg = (
            f"Baseline probability ({prob:.1%}). "
            f"No defensive action required. Continue standard monitoring."
        )

    return AgentClaim(
        agent="Guardian",
        role="Defense Advisor",
        emoji=":shield:",
        statement=msg,
        evidence=[
            f"Readiness level: {readiness}",
            f"Assets at risk: {assets}",
            f"Lead time: {lead_windows} windows"
            if lead_windows is not None
            else "Lead time: not crossed",
            f"Predicted stage: {stage}",
        ],
        confidence=prob,
        targets=["Analyst"],
    )


def _skeptic_round1(
    result: Any, history: list[Any], features: list[tuple[str, float]], assets: int
) -> AgentClaim:
    prob = result.predicted_stage.probability
    stage = result.predicted_stage.name
    conf = result.predicted_stage.confidence
    event_count = len(history)

    weaknesses = []
    if event_count < 10:
        weaknesses.append(
            f"Only {event_count} windows of history — insufficient for reliable forecasting"
        )
    if conf == "low":
        weaknesses.append("Model confidence is low — predictions may be noise")
    if prob < 0.3:
        weaknesses.append(
            "Probability near baseline — the model may be detecting normal traffic variation"
        )
    if assets < 3:
        weaknesses.append(f"Only {assets} assets observed — limited attack surface visibility")

    # Check for contradictory signals
    if features:
        top_name, top_val = features[0]
        if top_val < 0.5:
            weaknesses.append(
                f"Top feature '{top_name}' has weak signal ({top_val:.3f}) — "
                "the model's decision boundary is uncertain"
            )

    # Check if probability is volatile across windows
    probs = [getattr(w, "probability", 0) for w in history[-5:] if hasattr(w, "probability")]
    if probs:
        std = (sum((p - sum(probs) / len(probs)) ** 2 for p in probs) / len(probs)) ** 0.5
        if std > 0.15:
            weaknesses.append(
                f"Probability volatility (σ={std:.3f}) across last windows — "
                "unstable prediction may not persist"
            )

    if not weaknesses:
        weaknesses.append("No significant weaknesses detected in this forecast")

    assessment = (
        f"The forecast of {stage} at {prob:.1%} has {len(weaknesses)} concern(s). "
        f"The strongest challenge: {weaknesses[0]}"
    )

    return AgentClaim(
        agent="Skeptic",
        role="Devil's Advocate",
        emoji=":thinking:",
        statement=assessment,
        evidence=weaknesses,
        confidence=1 - prob,
        targets=["Guardian", "Analyst"],
    )


def _synthesizer_round1(
    analyst: AgentClaim,
    guardian: AgentClaim,
    skeptic: AgentClaim,
) -> AgentClaim:
    """Synthesizer summarizes the three positions."""
    evidence = [
        f"Analyst confidence: {analyst.confidence:.1%}",
        f"Guardian confidence: {guardian.confidence:.1%}",
        f"Skeptic concerns: {len(skeptic.evidence)}",
    ]
    return AgentClaim(
        agent="Synthesizer",
        role="Mediator",
        emoji=":",
        statement=(
            f"Three perspectives presented: {analyst.agent} sees "
            f"{analyst.confidence:.1%} probability, {guardian.agent} recommends "
            f"{guardian.evidence[0] if guardian.evidence else 'monitoring'}, "
            f"and {skeptic.agent} raises {len(skeptic.evidence)} concern(s). "
            "Entering debate round."
        ),
        evidence=evidence,
        confidence=0.5,
        targets=[],
    )


# ── Round 2: Agents respond to each other ────────────────────────────


def _analyst_round2(result: Any, skeptic: AgentClaim, guardian: AgentClaim) -> AgentResponse:
    rebuttal_parts = []
    for concern in skeptic.evidence[:2]:
        if "insufficient" in concern.lower():
            rebuttal_parts.append(
                "While history is short, the model is designed for rolling windows — "
                "it needs exactly the data available at the forecast moment."
            )
        elif "low" in concern.lower() and "confidence" in concern.lower():
            rebuttal_parts.append(
                "Low confidence on this window doesn't invalidate the probability — "
                "it means the model acknowledges uncertainty, which is honest behavior."
            )
        elif "volatile" in concern.lower():
            rebuttal_parts.append(
                "Volatility across windows is expected during active attack phases — "
                "the stage transitions cause natural probability shifts."
            )
        elif "near baseline" in concern.lower():
            rebuttal_parts.append(
                "The probability is above the calibrated baseline of 0.05 — "
                "it represents a real deviation from normal traffic patterns."
            )
        elif "weak signal" in concern.lower():
            rebuttal_parts.append(
                "Feature importance is relative — the top feature drives the prediction "
                "even if its absolute value seems low in the standardized space."
            )
        else:
            rebuttal_parts.append(
                "That concern is noted but does not override the measured probability."
            )

    if not rebuttal_parts:
        rebuttal_parts.append(
            "The data supports the current assessment without major contradictions."
        )

    return AgentResponse(
        agent="Analyst",
        role="Data Analyst",
        emoji=":",
        responds_to="Skeptic",
        rebuttal=" ".join(rebuttal_parts),
    )


def _guardian_round2(result: Any, skeptic: AgentClaim, analyst: AgentClaim) -> AgentResponse:
    prob = result.predicted_stage.probability

    if prob >= 0.5:
        rebuttal = (
            "Even with the Skeptic's concerns, the cost of inaction on a "
            f"{prob:.1%} probability exceeds the cost of preparing defenses. "
            "Defensive posture should be proportional to probability, not "
            "certainty. I maintain my recommendation for elevated monitoring."
        )
    else:
        rebuttal = (
            "The Skeptic's concerns about low probability are well-founded. "
            f"At {prob:.1%}, the risk does not justify preemptive action. "
            "Standard monitoring is appropriate."
        )

    return AgentResponse(
        agent="Guardian",
        role="Defense Advisor",
        emoji=":shield:",
        responds_to="Skeptic",
        rebuttal=rebuttal,
    )


def _skeptic_round2(result: Any, analyst: AgentClaim, guardian: AgentClaim) -> AgentResponse:
    prob = result.predicted_stage.probability

    if prob >= 0.8:
        rebuttal = (
            "I accept the Analyst's data-driven assessment but note that "
            "high confidence on synthetic data does not guarantee real-world "
            "accuracy. The Guardian's action recommendation is sound as a "
            "precaution, but the underlying probability may overstate the "
            "actual threat on live traffic."
        )
    elif prob >= 0.5:
        rebuttal = (
            "The Analyst's evidence is reasonable, but the threshold between "
            "'elevated' and 'critical' matters for resource allocation. "
            f"At {prob:.1%}, we are in the gray zone — the Guardian should "
            "prepare but not over-commit resources."
        )
    else:
        rebuttal = (
            "I concur with the Analyst that the probability is low. "
            "The Guardian correctly recommends standard monitoring. "
            "However, I note that this assessment applies to the current "
            "window only — the situation may change rapidly."
        )

    return AgentResponse(
        agent="Skeptic",
        role="Devil's Advocate",
        emoji=":thinking:",
        responds_to="Analyst",
        rebuttal=rebuttal,
    )


# ── Round 3: Synthesizer produces final verdict ─────────────────────


def _synthesizer_round3(
    result: Any,
    round1_claims: list[AgentClaim],
    round2_responses: list[AgentResponse],
) -> dict[str, str]:
    prob = result.predicted_stage.probability
    stage = result.predicted_stage.name
    lead = result.lead_time
    lead_windows = lead.lead_windows if lead else None

    high_prob = prob >= 0.5
    has_lead = lead_windows is not None and lead_windows >= 1

    # Build verdict
    if high_prob and has_lead:
        verdict = (
            f"CONSENSUS: {stage} at {prob:.1%} probability with {lead_windows}-window "
            f"lead. All agents agree this warrants action. The Analyst confirms the "
            f"data, the Guardian recommends preparation, and the Skeptic acknowledges "
            f"the evidence while noting real-data validation is pending. "
            f"Recommended: pre-position containment and increase monitoring."
        )
    elif high_prob:
        verdict = (
            f"CONSENSUS: {stage} at {prob:.1%} probability, but no prediction lead "
            f"time available. The Analyst confirms the data supports elevated concern. "
            f"The Guardian recommends monitoring readiness. The Skeptic flags the "
            f"lack of lead time as a constraint on preemptive action. "
            f"Recommended: heightened monitoring with contingency plans ready."
        )
    else:
        verdict = (
            f"CONSENSUS: {stage} at {prob:.1%} — below the action threshold. "
            f"The Analyst confirms low probability, the Guardian concurs standard "
            f"monitoring is sufficient, and the Skeptic finds no urgent concerns. "
            f"Recommended: continue routine monitoring."
        )

    # Action items
    action_items = []
    if prob >= 0.8:
        action_items.append("Activate incident response team")
        action_items.append("Pre-position containment controls on observed assets")
        action_items.append("Notify stakeholders of elevated risk")
    elif prob >= 0.5:
        action_items.append("Increase monitoring frequency on observed assets")
        action_items.append("Review and update containment playbooks")
        action_items.append("Brief SOC on predicted stage transition")
    elif prob >= 0.2:
        action_items.append("Continue standard monitoring")
        action_items.append("Document the forecast for trend analysis")
    else:
        action_items.append("No action required — baseline traffic")

    # Consensus score: agreement between agents
    agent_probs = [c.confidence for c in round1_claims if c.agent != "Synthesizer"]
    if agent_probs:
        consensus = 1 - (max(agent_probs) - min(agent_probs))
    else:
        consensus = 0.5

    return {
        "verdict": verdict,
        "consensus_score": f"{consensus:.1%}",
        "action_items": "\n".join(f"- {item}" for item in action_items),
    }


# ── Main conference entry point ──────────────────────────────────────


def run_conference(
    result: Any,
    scenario_states: list[Any],
    scenario_id: str,
    cut: int,
) -> ConferenceResult:
    """Run the full 3-round agent conference on the current forecast."""
    history = scenario_states[:cut]
    features = _top_features(result, history)
    assets = _asset_count(history)

    # Round 1
    analyst_r1 = _analyst_round1(result, history, features, assets)
    guardian_r1 = _guardian_round1(result, history, features, assets)
    skeptic_r1 = _skeptic_round1(result, history, features, assets)
    synthesizer_r1 = _synthesizer_round1(analyst_r1, guardian_r1, skeptic_r1)
    round1 = [analyst_r1, guardian_r1, skeptic_r1, synthesizer_r1]

    # Round 2
    analyst_r2 = _analyst_round2(result, skeptic_r1, guardian_r1)
    guardian_r2 = _guardian_round2(result, skeptic_r1, analyst_r1)
    skeptic_r2 = _skeptic_round2(result, analyst_r1, guardian_r1)
    round2 = [analyst_r2, guardian_r2, skeptic_r2]

    # Round 3
    round3 = _synthesizer_round3(result, round1, round2)

    stage_rationale = ""
    stage_evidence = []
    if result.stage_mapping is not None:
        stage_rationale = result.stage_mapping.rationale or ""
        stage_evidence = [
            {
                "description": ev.description,
                "observed_value": ev.observed_value,
                "confidence": ev.confidence,
            }
            for ev in (result.stage_mapping.evidence or [])
        ]

    return ConferenceResult(
        scenario=scenario_id,
        window=cut,
        peak_probability=result.predicted_stage.probability,
        predicted_stage=result.predicted_stage.name,
        confidence=result.predicted_stage.confidence,
        lead_windows=result.lead_time.lead_windows if result.lead_time else None,
        stage_rationale=stage_rationale,
        stage_evidence=stage_evidence,
        top_features=features,
        round1=round1,
        round2=round2,
        round3=round3,
        verdict=round3["verdict"],
        consensus_score=float(round3["consensus_score"].rstrip("%")) / 100,
        action_items=[
            line.lstrip("- ") for line in round3["action_items"].split("\n") if line.strip()
        ],
    )
