from datetime import UTC, datetime, timedelta

import pytest

from sentinel.schemas import NetworkState, StateLabel
from sentinel.targets import (
    LabelledState,
    build_sequence_samples,
    build_transition_targets,
    make_split_manifest,
    make_state_key,
)

START = datetime(2026, 1, 1, tzinfo=UTC)


def labelled(index: int, scenario_id: str = "scenario-a") -> LabelledState:
    state = NetworkState(
        window_start=START + timedelta(minutes=index),
        window_end=START + timedelta(minutes=index + 1),
        features={"event_count": float(index)},
        coverage={"flow": True, "packet": False},
    )
    return LabelledState(
        state_key=make_state_key(state, index),
        scenario_id=scenario_id,
        state=state,
        label=StateLabel(
            state_key=make_state_key(state, index),
            scenario_id=scenario_id,
            infiltration=index >= 2,
            attack_stage="Lateral Movement" if index >= 2 else "Reconnaissance",
            label_source="replay",
        ),
    )


def test_transition_target_uses_future_state_without_crossing_scenarios() -> None:
    states = [labelled(index) for index in range(3)] + [labelled(3, "scenario-b")]

    targets = build_transition_targets(states, horizon=1)

    assert len(targets) == 2
    assert all(target.scenario_id == "scenario-a" for target in targets)
    assert targets[0].target_infiltration is False
    assert targets[1].target_infiltration is True


def test_sequence_samples_require_contiguous_same_scenario() -> None:
    states = [labelled(index) for index in range(3)] + [labelled(3, "scenario-b")]

    samples = build_sequence_samples(states, sequence_length=2, horizon=1)

    assert len(samples) == 1
    assert samples[0].scenario_id == "scenario-a"
    assert samples[0].input_state_keys[-1] != samples[0].target.target_state_key


def test_split_manifest_has_disjoint_scenario_sets() -> None:
    manifest = make_split_manifest(["a", "b", "c", "d", "e"], seed=7)

    train = set(manifest.train_scenarios)
    validation = set(manifest.validation_scenarios)
    test = set(manifest.test_scenarios)
    assert train.isdisjoint(validation)
    assert train.isdisjoint(test)
    assert validation.isdisjoint(test)
    assert train | validation | test == {"a", "b", "c", "d", "e"}


def test_invalid_target_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="horizon must be positive"):
        build_transition_targets([], horizon=0)


def test_stratified_split_balances_attack_classes() -> None:
    from collections import Counter

    from sentinel.targets import make_stratified_split_manifest

    # Two classes, six scenarios: round-robin dealing must put both classes
    # in every split (the random split could stack all DDoS into one split).
    scenarios = ["ddos-1", "ddos-2", "ddos-3", "portscan-1", "portscan-2", "portscan-3"]
    stages = {
        s: ("Denial of Service" if s.startswith("ddos") else "Reconnaissance") for s in scenarios
    }
    manifest = make_stratified_split_manifest(scenarios, stages, seed=5)
    all_assigned = (
        manifest.train_scenarios + manifest.validation_scenarios + manifest.test_scenarios
    )
    assert sorted(all_assigned) == sorted(scenarios)  # nothing lost, nothing doubled
    for split in (manifest.train_scenarios, manifest.validation_scenarios, manifest.test_scenarios):
        classes = Counter(stages[s] for s in split)
        assert classes["Denial of Service"] >= 1
        assert classes["Reconnaissance"] >= 1


def test_stratified_split_rejects_unknown_stage() -> None:
    import pytest

    from sentinel.targets import make_stratified_split_manifest

    with pytest.raises(ValueError, match="stage missing"):
        make_stratified_split_manifest(["a", "b"], {"a": "Benign"}, seed=1)
