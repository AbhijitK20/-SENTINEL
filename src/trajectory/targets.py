"""Build labels, future targets, and leakage-safe sequence samples."""

from __future__ import annotations

import random
from dataclasses import dataclass

from trajectory.schemas import (
    NetworkState,
    SequenceSample,
    SplitManifest,
    StateLabel,
    TransitionTarget,
)


@dataclass(frozen=True)
class LabelledState:
    """A state paired with its scenario and explicit label."""

    state_key: str
    scenario_id: str
    state: NetworkState
    label: StateLabel


def make_state_key(state: NetworkState, index: int) -> str:
    """Create a stable key without using labels or future information."""
    return f"{state.window_start.isoformat()}::{index}"


def build_transition_targets(
    labelled_states: list[LabelledState],
    *,
    horizon: int,
) -> list[TransitionTarget]:
    """Create future targets only within the same scenario."""
    if horizon < 1:
        raise ValueError("horizon must be positive")

    targets: list[TransitionTarget] = []
    for source_index, source in enumerate(labelled_states):
        target_index = source_index + horizon
        if target_index >= len(labelled_states):
            continue
        target = labelled_states[target_index]
        if target.scenario_id != source.scenario_id:
            continue
        targets.append(
            TransitionTarget(
                source_state_key=source.state_key,
                target_state_key=target.state_key,
                horizon=horizon,
                scenario_id=source.scenario_id,
                target_features=target.state.features,
                target_infiltration=target.label.infiltration,
                target_stage=target.label.attack_stage,
            )
        )
    return targets


def build_sequence_samples(
    labelled_states: list[LabelledState],
    *,
    sequence_length: int,
    horizon: int,
) -> list[SequenceSample]:
    """Build contiguous same-scenario input sequences and future targets."""
    if sequence_length < 1:
        raise ValueError("sequence_length must be positive")
    if horizon < 1:
        raise ValueError("horizon must be positive")

    samples: list[SequenceSample] = []
    for end_index in range(sequence_length - 1, len(labelled_states) - horizon):
        window = labelled_states[end_index - sequence_length + 1 : end_index + 1]
        source = window[-1]
        target_state = labelled_states[end_index + horizon]
        if any(item.scenario_id != source.scenario_id for item in window):
            continue
        if target_state.scenario_id != source.scenario_id:
            continue
        target = TransitionTarget(
            source_state_key=source.state_key,
            target_state_key=target_state.state_key,
            horizon=horizon,
            scenario_id=source.scenario_id,
            target_features=target_state.state.features,
            target_infiltration=target_state.label.infiltration,
            target_stage=target_state.label.attack_stage,
        )
        samples.append(
            SequenceSample(
                sample_id=f"{source.scenario_id}:{end_index}",
                scenario_id=source.scenario_id,
                input_state_keys=[item.state_key for item in window],
                target=target,
            )
        )
    return samples


def make_split_manifest(
    scenario_ids: list[str],
    *,
    seed: int = 42,
    train_fraction: float = 0.6,
    validation_fraction: float = 0.2,
) -> SplitManifest:
    """Assign complete scenarios to splits, never individual windows."""
    if not 0 < train_fraction < 1 or not 0 <= validation_fraction < 1:
        raise ValueError("split fractions must be between zero and one")
    if train_fraction + validation_fraction >= 1:
        raise ValueError("train and validation fractions must leave test data")

    unique_ids = sorted(set(scenario_ids))
    shuffled = list(unique_ids)
    random.Random(seed).shuffle(shuffled)
    train_end = int(len(shuffled) * train_fraction)
    validation_end = train_end + int(len(shuffled) * validation_fraction)
    if len(shuffled) >= 3:
        train_end = max(1, train_end)
        validation_end = max(train_end + 1, validation_end)
        validation_end = min(validation_end, len(shuffled) - 1)

    return SplitManifest(
        seed=seed,
        train_scenarios=sorted(shuffled[:train_end]),
        validation_scenarios=sorted(shuffled[train_end:validation_end]),
        test_scenarios=sorted(shuffled[validation_end:]),
    )
