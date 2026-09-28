"""Tests for ATT&CK Flow sequence extraction and transition estimation."""

from __future__ import annotations

from sentinel.attack_sequences import (
    TransitionModel,
    extract_sequences,
    load_attack_flow_bundle,
)

# ── Fixtures ──────────────────────────────────────────────────────────

SIMPLE_FLOW_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test-001",
    "spec_version": "2.1",
    "created": "2025-01-01T00:00:00Z",
    "objects": [
        {
            "type": "attack-flow",
            "id": "flow--f1",
            "start_refs": ["action--a1"],
            "name": "Test Flow",
        },
        {
            "type": "attack-action",
            "id": "action--a1",
            "name": "Recon",
            "technique_id": "T1595",
            "effect_refs": ["action--a2"],
        },
        {
            "type": "attack-action",
            "id": "action--a2",
            "name": "Initial Access",
            "technique_id": "T1190",
            "effect_refs": ["action--a3"],
        },
        {
            "type": "attack-action",
            "id": "action--a3",
            "name": "Lateral Movement",
            "technique_id": "T1021",
            "effect_refs": [],
        },
    ],
}

CONDITIONAL_FLOW_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test-002",
    "spec_version": "2.1",
    "created": "2025-01-01T00:00:00Z",
    "objects": [
        {
            "type": "attack-flow",
            "id": "flow--f2",
            "start_refs": ["action--c1"],
            "name": "Conditional Flow",
        },
        {
            "type": "attack-action",
            "id": "action--c1",
            "name": "Phishing",
            "technique_id": "T1566",
            "effect_refs": ["condition--cond1"],
        },
        {
            "type": "attack-condition",
            "id": "condition--cond1",
            "name": "Success?",
            "on_true_refs": ["action--c2"],
            "on_false_refs": ["action--c3"],
        },
        {
            "type": "attack-action",
            "id": "action--c2",
            "name": "Credential Dump",
            "technique_id": "T1003",
            "effect_refs": [],
        },
        {
            "type": "attack-action",
            "id": "action--c3",
            "name": "Malware",
            "technique_id": "T1059",
            "effect_refs": [],
        },
    ],
}

EMPTY_FLOW_BUNDLE = {
    "type": "bundle",
    "id": "bundle--empty",
    "spec_version": "2.1",
    "created": "2025-01-01T00:00:00Z",
    "objects": [
        {
            "type": "attack-flow",
            "id": "flow--f3",
            "start_refs": [],
            "name": "Empty Flow",
        },
    ],
}


# ── Extraction tests ───────────────────────────────────────────────────


def test_simple_flow_extracts_technique_sequence() -> None:
    sequences = extract_sequences(SIMPLE_FLOW_BUNDLE)
    assert len(sequences) == 1
    assert sequences[0] == ["T1595", "T1190", "T1021"]


def test_conditional_flow_extracts_both_branches() -> None:
    sequences = extract_sequences(CONDITIONAL_FLOW_BUNDLE)
    assert len(sequences) >= 2
    # Both branches should appear
    technique_sets = [set(seq) for seq in sequences]
    assert {"T1566", "T1003"} in technique_sets
    assert {"T1566", "T1059"} in technique_sets


def test_empty_flow_returns_no_sequences() -> None:
    sequences = extract_sequences(EMPTY_FLOW_BUNDLE)
    assert sequences == []


def test_missing_technique_id_skips_action() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--no-tech",
        "spec_version": "2.1",
        "objects": [
            {"type": "attack-flow", "id": "f1", "start_refs": ["a1"]},
            {"type": "attack-action", "id": "a1", "name": "No tech", "effect_refs": []},
        ],
    }
    sequences = extract_sequences(bundle)
    assert sequences == []


def test_missing_start_refs_returns_no_sequences() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--no-start",
        "spec_version": "2.1",
        "objects": [
            {"type": "attack-action", "id": "a1", "technique_id": "T1190"},
        ],
    }
    sequences = extract_sequences(bundle)
    assert sequences == []


# ── Bundle loading tests ──────────────────────────────────────────────


def test_load_bundle_from_dict() -> None:
    bundle = load_attack_flow_bundle(SIMPLE_FLOW_BUNDLE)
    assert bundle["spec_version"] == "2.1"


def test_bundle_provenance_includes_checksum() -> None:
    bundle = load_attack_flow_bundle(SIMPLE_FLOW_BUNDLE)
    assert "source_sha256" in bundle


# ── Transition model tests ────────────────────────────────────────────


def test_transition_model_from_sequences() -> None:
    sequences = [
        ["T1595", "T1190", "T1021"],
        ["T1595", "T1190", "T1059"],
        ["T1566", "T1003", "T1021"],
    ]
    model = TransitionModel.from_sequences(
        sequences,
        smoothing=0.1,
        min_support=1,
        provenance={"source": "test"},
    )
    assert model.transition_count("T1595", "T1190") == 2
    assert model.transition_count("T1190", "T1021") == 1
    assert model.transition_count("T1566", "T1003") == 1


def test_transition_model_low_support_filtered() -> None:
    sequences = [
        ["T1595", "T1190"],
        ["T1566", "T1003"],
    ]
    model = TransitionModel.from_sequences(
        sequences,
        smoothing=0.1,
        min_support=2,  # require at least 2 observations
        provenance={"source": "test"},
    )
    # T1595->T1190 only seen once, below min_support
    candidates = model.predict("T1595", top_k=3)
    # Should return empty or only high-support transitions
    assert all(c.support >= 2 for c in candidates) or len(candidates) == 0


def test_transition_model_empty_sequences() -> None:
    model = TransitionModel.from_sequences([], provenance={"source": "test"})
    assert model.predict("T1595") == []


def test_transition_model_predict_unknown_source() -> None:
    model = TransitionModel.from_sequences(
        [["T1595", "T1190"]],
        provenance={"source": "test"},
    )
    candidates = model.predict("UNKNOWN", top_k=3)
    assert candidates == []


# ── Evaluation tests ──────────────────────────────────────────────────


def test_evaluation_split_by_scenario() -> None:
    """Train/test split must be by scenario, not by individual transitions."""
    sequences = [
        ["T1595", "T1190", "T1021"],  # scenario A
        ["T1595", "T1190", "T1059"],  # scenario A
        ["T1566", "T1003", "T1021"],  # scenario B
    ]
    train_idx = [0, 1]
    test_idx = [2]

    model = TransitionModel.from_sequences(
        [sequences[i] for i in train_idx],
        provenance={"source": "test", "split": "80-20"},
    )

    # Evaluate on test set
    correct = 0
    total = 0
    for idx in test_idx:
        seq = sequences[idx]
        for i in range(1, len(seq)):
            candidates = model.predict(seq[i - 1], top_k=1)
            if candidates and candidates[0].technique == seq[i]:
                correct += 1
            total += 1

    assert total > 0
    # Just verify it runs without error; accuracy check is PENDING
    # until we have real data
