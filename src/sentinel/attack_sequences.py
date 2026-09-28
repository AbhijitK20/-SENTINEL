# SPDX-License-Identifier: Apache-2.0
"""ATT&CK Flow sequence extraction and transition estimation.

Extracts technique sequences from STIX 2.1 Attack Flow bundles and
estimates first-order Markov transition probabilities with support counts.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class TransitionCandidate:
    """One predicted next technique with probability and support."""

    technique: str
    probability: float
    support: int


@dataclass
class TransitionModel:
    """First-order Markov transition model derived from ATT&CK sequences."""

    start_counts: dict[str, int] = field(default_factory=dict)
    transition_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    total_starts: int = 0
    total_transitions: int = 0
    provenance: dict = field(default_factory=dict)
    smoothing: float = 0.0
    min_support: int = 1

    @classmethod
    def from_sequences(
        cls,
        sequences: list[list[str]],
        *,
        smoothing: float = 0.1,
        min_support: int = 1,
        provenance: dict | None = None,
    ) -> TransitionModel:
        """Build transition model from technique sequences."""
        start_counts: dict[str, int] = defaultdict(int)
        trans_counts: dict[tuple[str, str], int] = defaultdict(int)

        for seq in sequences:
            if not seq:
                continue
            start_counts[seq[0]] += 1
            for a, b in zip(seq[:-1], seq[1:], strict=False):
                trans_counts[(a, b)] += 1

        total_starts = sum(start_counts.values())
        total_transitions = sum(trans_counts.values())

        return cls(
            start_counts=dict(start_counts),
            transition_counts=dict(trans_counts),
            total_starts=total_starts,
            total_transitions=total_transitions,
            provenance=provenance or {},
            smoothing=smoothing,
            min_support=min_support,
        )

    def transition_count(self, source: str, target: str) -> int:
        return self.transition_counts.get((source, target), 0)

    def predict(self, current: str, top_k: int = 3) -> list[TransitionCandidate]:
        """Predict next techniques from current, filtering by min_support."""
        candidates: list[TransitionCandidate] = []
        for (src, tgt), count in self.transition_counts.items():
            if src != current:
                continue
            if count < self.min_support:
                continue
            # Normalize with additive smoothing
            row_total = sum(c for (s, _), c in self.transition_counts.items() if s == current)
            vocab_size = len({t for (s, t) in self.transition_counts if s == current})
            prob = (count + self.smoothing) / (row_total + self.smoothing * vocab_size)
            candidates.append(
                TransitionCandidate(technique=tgt, probability=round(prob, 4), support=count)
            )

        candidates.sort(key=lambda c: -c.probability)
        return candidates[:top_k]


def load_attack_flow_bundle(bundle_data: dict) -> dict:
    """Load and record provenance for an ATT&CK Flow bundle."""
    raw = json.dumps(bundle_data, sort_keys=True).encode()
    sha = hashlib.sha256(raw).hexdigest()
    return {**bundle_data, "source_sha256": sha}


def extract_sequences(bundle: dict) -> list[list[str]]:
    """Extract technique sequences from a STIX 2.1 Attack Flow bundle.

    Follows start_refs → attack-action → effect_refs / condition branches.
    Skips actions without technique_id.
    """
    objects = bundle.get("objects", [])
    by_id = {o.get("id"): o for o in objects if o.get("id")}

    # Find start references from attack-flow objects
    start_refs: list[str] = []
    for obj in objects:
        if obj.get("type") == "attack-flow":
            start_refs.extend(obj.get("start_refs", []))

    sequences: list[list[str]] = []
    for start in start_refs:
        paths: list[list[str]] = []
        _dfs(start, [], paths, by_id, visited=set())
        sequences.extend(paths)

    return sequences


def _dfs(
    node_id: str,
    current_path: list[str],
    all_paths: list[list[str]],
    by_id: dict,
    visited: set[str],
) -> None:
    """DFS traversal of attack-action nodes following effect/condition refs."""
    if node_id in visited:
        return
    visited = visited | {node_id}

    obj = by_id.get(node_id)
    if obj is None:
        return

    node_type = obj.get("type")

    if node_type == "attack-action":
        tech = obj.get("technique_id")
        if tech:
            current_path = current_path + [tech]
        # Follow effect_refs
        for ref in obj.get("effect_refs", []):
            _dfs(ref, current_path, all_paths, by_id, visited)
        # If no effect_refs, this is a leaf
        if not obj.get("effect_refs") and current_path:
            all_paths.append(current_path)

    elif node_type == "attack-condition":
        # Branch into true/false paths
        for ref in obj.get("on_true_refs", []):
            _dfs(ref, current_path, all_paths, by_id, visited)
        for ref in obj.get("on_false_refs", []):
            _dfs(ref, current_path, all_paths, by_id, visited)

    elif node_type == "attack-operator":
        for ref in obj.get("effect_refs", []):
            _dfs(ref, current_path, all_paths, by_id, visited)
