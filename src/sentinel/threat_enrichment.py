# SPDX-License-Identifier: Apache-2.0
"""Threat intelligence enrichment: Markov transitions and entropy analysis.

``TRANSITIONS`` below is a **literal prior table**, not a measurement. It is
what the product falls back to when no ATT&CK Flow data is supplied. To get
probabilities derived from real intrusion sequences instead, point
``SENTINEL_ATTACK_FLOW_DIR`` at a directory of MITRE ATT&CK Flow STIX bundles
(see ``research/ATTACK_FLOW_PROVENANCE.md``); the API then reports
``transition_source()`` as ``attack-flow-data:N-bundles`` so a caller can tell
the two apart. The bundles are not committed, so that path only runs for
whoever supplies the data.

Entropy functions support anomaly detection on DNS query-name labels.

No hand-authored EPSS/KEV technique estimates are used for risk scoring.
"""

from __future__ import annotations

import json
import math
import os
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sentinel.attack_sequences import TransitionModel

# ─── Kill chain transitions (Markov model) ──────────────────────────────

# First-order Markov transition priors. LITERAL VALUES, not measured: see the
# module docstring. Replace them by supplying ATT&CK Flow data.
TRANSITIONS: dict[tuple[str, str], float] = {
    ("reconnaissance", "credential_abuse"): 0.72,
    ("reconnaissance", "lateral_movement"): 0.45,
    ("reconnaissance", "command_and_control"): 0.30,
    ("credential_abuse", "lateral_movement"): 0.85,
    ("credential_abuse", "command_and_control"): 0.55,
    ("credential_abuse", "exfiltration"): 0.35,
    ("lateral_movement", "exfiltration"): 0.70,
    ("lateral_movement", "command_and_control"): 0.60,
    ("lateral_movement", "malware_activity"): 0.40,
    ("command_and_control", "exfiltration"): 0.80,
    ("command_and_control", "malware_activity"): 0.50,
    ("exfiltration", "command_and_control"): 0.25,
    ("ddos", "reconnaissance"): 0.30,
    ("ddos", "credential_abuse"): 0.20,
    ("insider_threat", "exfiltration"): 0.65,
    ("insider_threat", "lateral_movement"): 0.45,
    ("malware_activity", "lateral_movement"): 0.55,
    ("malware_activity", "exfiltration"): 0.40,
}

# Start-state priors. LITERAL VALUES, not measured: see the module docstring.
START_PROBS: dict[str, float] = {
    "reconnaissance": 0.35,
    "ddos": 0.15,
    "phishing": 0.20,
    "credential_abuse": 0.15,
    "malware_activity": 0.10,
    "insider_threat": 0.05,
}


def transition_likelihood(current_type: str, next_type: str) -> float:
    """P(next | current) from Markov transition table."""
    return TRANSITIONS.get((current_type, next_type), 0.1)


def markov_chain_prob(sequence: list[str]) -> float:
    """P(sequence) under the first-order Markov model.

    P(seq) = P_start(t_0) * product(P(t_i | t_{i-1}))
    """
    if not sequence:
        return 0.0
    log_p = math.log(max(START_PROBS.get(sequence[0], 0.05), 1e-12))
    for a, b in zip(sequence[:-1], sequence[1:], strict=False):
        p = TRANSITIONS.get((a, b), 0.05)
        log_p += math.log(max(p, 1e-12))
    return math.exp(log_p)


# ─── Next-technique prediction ──────────────────────────────────────────

#: Populated by :func:`load_attack_flow_transitions` when the user supplies a
#: directory of MITRE ATT&CK Flow bundles. ``None`` means "no data supplied",
#: and the literal table above is the fallback. A prediction always reports
#: which of the two produced it, so a number is never silently attributed to
#: campaign data it was not derived from.
_FLOW_MODEL: TransitionModel | None = None


def load_attack_flow_transitions(directory: str | os.PathLike[str]) -> bool:
    """Derive transition probabilities from local ATT&CK Flow STIX bundles.

    The bundles are not committed (see ``research/ATTACK_FLOW_PROVENANCE.md``),
    so the caller supplies the directory. Returns True when a model was built.
    """
    global _FLOW_MODEL  # noqa: PLW0603 - one process-wide derived model
    from sentinel.attack_sequences import (  # noqa: PLC0415 - optional, data-dependent
        TransitionModel,
        extract_sequences,
        load_attack_flow_bundle,
    )

    sequences: list[list[str]] = []
    sources: list[str] = []
    for path in sorted(Path(directory).glob("*.json")):
        bundle = load_attack_flow_bundle(json.loads(path.read_text(encoding="utf-8")))
        found = [_to_stage_names(seq) for seq in extract_sequences(bundle)]
        found = [seq for seq in found if seq]
        if found:
            sequences.extend(found)
            sources.append(bundle["source_sha256"][:12])
    if not sequences:
        _FLOW_MODEL = None
        return False
    _FLOW_MODEL = TransitionModel.from_sequences(
        sequences,
        min_support=1,
        provenance={"bundles": len(sources), "sequences": len(sequences)},
    )
    return True


def _to_stage_names(sequence: list[str]) -> list[str]:
    """Map ATT&CK technique ids to the attack-type vocabulary findings use.

    The bundles are keyed by technique (``T1566.001``) while detectors emit
    attack types (``phishing``). ``detectors.MITRE`` is the existing
    attack-type -> technique map, so inverting it keeps one vocabulary on both
    sides. Sub-techniques match on their parent id.
    """
    from sentinel.detectors import MITRE  # noqa: PLC0415 - avoid an import cycle

    by_technique = {technique: attack_type for attack_type, technique in MITRE.items()}
    mapped: list[str] = []
    for technique in sequence:
        attack_type = by_technique.get(technique) or by_technique.get(technique.split(".")[0])
        if attack_type and attack_type not in mapped:
            mapped.append(attack_type)
    return mapped


def transition_source() -> str:
    """Which transition table produced the current predictions."""
    if _FLOW_MODEL is None:
        return "literal-prior-table"
    return f"attack-flow-data:{_FLOW_MODEL.provenance.get('bundles', 0)}-bundles"


def predict_next_techniques(observed: list[str], top_k: int = 3) -> list[tuple[str, float]]:
    """Predict the most likely next techniques given observed sequence.

    Uses ATT&CK Flow data when :func:`load_attack_flow_transitions` supplied it,
    otherwise the literal prior table. Returns:
    [(technique, probability), ...] sorted by probability desc.
    """
    if _FLOW_MODEL is not None:
        if not observed:
            starts = {
                technique: _FLOW_MODEL.start_counts[technique] / _FLOW_MODEL.total_starts
                for technique in _FLOW_MODEL.start_counts
            }
            return sorted(starts.items(), key=lambda x: -x[1])[:top_k]
        candidates = [(c.technique, c.probability) for c in _FLOW_MODEL.predict(observed[-1])]
        if candidates:
            return sorted(candidates, key=lambda x: -x[1])[:top_k]

    if not observed:
        # Return start-state probabilities
        return sorted(START_PROBS.items(), key=lambda x: -x[1])[:top_k]

    last = observed[-1]
    candidates = {b: p for (a, b), p in TRANSITIONS.items() if a == last}

    if not candidates:
        return []

    return sorted(candidates.items(), key=lambda x: -x[1])[:top_k]


# ─── Shannon entropy (from sentinel-dns) ────────────────────────────────


def shannon_entropy(data: list[float]) -> float:
    """Shannon entropy of a value distribution.

    H = -sum(p_i * log2(p_i))
    From sentinel-dns: threshold 3.8 for DNS anomaly detection.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def entropy_anomaly_score(
    current_entropy: float, history_entropies: list[float], threshold: float = 3.8
) -> float:
    """Score based on entropy deviation from baseline.

    From sentinel-dns: domains with entropy > 3.8 are suspicious.
    Here we compare against baseline history for adaptive thresholding.
    """
    if not history_entropies:
        # No baseline — use absolute threshold
        return min(1.0, max(0.0, (current_entropy - threshold) / 2.0))

    mean_ent = sum(history_entropies) / len(history_entropies)
    deviation = abs(current_entropy - mean_ent)

    # High deviation from baseline = anomalous
    return min(1.0, deviation / 3.0)
