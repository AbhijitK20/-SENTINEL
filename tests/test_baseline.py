import json
from pathlib import Path

import pytest

from trajectory.baseline import (
    SPLIT_NAMES,
    audit_split,
    save_baseline_artifacts,
    train_baseline,
)
from trajectory.config import BaselineConfig
from trajectory.schemas import SplitManifest
from trajectory.synthetic import generate_labelled_states, generate_scenario_events
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"s{index}" for index in range(5)]


def build_inputs(seed: int = 7):
    labelled = generate_labelled_states(SCENARIOS, seed=seed, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=3, horizon=2)
    manifest = make_split_manifest(SCENARIOS, seed=seed)
    return labelled, samples, manifest


def test_synthetic_scenarios_are_deterministic_and_staged() -> None:
    first, boundaries = generate_scenario_events("demo", seed=1)
    second, _ = generate_scenario_events("demo", seed=1)
    other, _ = generate_scenario_events("demo", seed=2)

    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]
    assert [e.event_id for e in first] != [e.event_id for e in other] or first != other
    assert boundaries["recon_start"] < boundaries["lateral_start"]
    assert any(e.features["failed_auth"] == 1.0 for e in first)


def test_split_audit_confirms_scenario_and_window_isolation() -> None:
    _, samples, manifest = build_inputs()

    audit = audit_split(samples, manifest)

    assert audit.disjoint_scenarios is True
    assert audit.disjoint_state_keys is True
    assert sum(audit.sample_counts.values()) == len(samples)
    assert set(audit.sample_counts) == set(SPLIT_NAMES)


def test_audit_rejects_scenarios_missing_from_manifest() -> None:
    _, samples, _ = build_inputs()
    manifest = SplitManifest(
        seed=0, train_scenarios=["s0", "s1"], validation_scenarios=["s2"], test_scenarios=[]
    )

    with pytest.raises(ValueError, match="missing from split manifest"):
        audit_split(samples, manifest)


def test_baseline_refuses_leaky_manifest() -> None:
    labelled, samples, _ = build_inputs()
    leaky = SplitManifest(
        seed=0,
        train_scenarios=SCENARIOS,
        validation_scenarios=[],
        test_scenarios=["s0"],
    )

    with pytest.raises(ValueError, match="multiple splits"):
        train_baseline(labelled, samples, leaky, config=BaselineConfig(), seed=0)


def test_baseline_trains_on_current_window_and_reports_all_splits() -> None:
    labelled, samples, manifest = build_inputs()
    config = BaselineConfig()

    run = train_baseline(labelled, samples, manifest, config=config, seed=7)
    result = run.result

    assert set(result.metrics) == set(SPLIT_NAMES)
    assert result.horizon == 2
    assert result.split_audit.disjoint_scenarios and result.split_audit.disjoint_state_keys
    for name in config.excluded_features:
        assert name not in result.feature_schema.names
    forbidden = {"infiltration", "attack_stage", "scenario_id", "target_infiltration"}
    assert forbidden.isdisjoint(result.feature_schema.names)
    test = result.metrics["test"]
    assert test.sample_count == result.split_audit.sample_counts["test"]
    assert all(
        value is None or 0.0 <= value <= 1.0
        for value in (test.precision, test.recall, test.f1, test.false_positive_rate)
    )
    assert len(result.feature_weights) == result.feature_schema.width


def test_baseline_is_reproducible_for_a_fixed_seed() -> None:
    labelled, samples, manifest = build_inputs()

    first = train_baseline(labelled, samples, manifest, config=BaselineConfig(), seed=7)
    second = train_baseline(labelled, samples, manifest, config=BaselineConfig(), seed=7)

    assert first.result.metrics == second.result.metrics
    assert first.result.feature_weights == second.result.feature_weights
    assert first.result.feature_schema == second.result.feature_schema


def test_artifacts_include_checksum_and_report(tmp_path: Path) -> None:
    labelled, samples, manifest = build_inputs()
    run = train_baseline(labelled, samples, manifest, config=BaselineConfig(), seed=7)

    paths = save_baseline_artifacts(run, tmp_path)

    payload = json.loads(paths["result"].read_text(encoding="utf-8"))
    assert len(payload["model_sha256"]) == 64
    assert payload["split_manifest"]["seed"] == 7
    report = paths["report"].read_text(encoding="utf-8")
    for heading in ("Precision", "Recall", "F1", "False-positive rate", "Split Audit"):
        assert heading in report
    assert paths["model"].stat().st_size > 0


def test_single_class_training_split_is_rejected() -> None:
    labelled, samples, manifest = build_inputs()
    only_benign = [
        sample
        for sample in samples
        if sample.scenario_id not in manifest.train_scenarios
        or not sample.target.target_infiltration
    ]

    with pytest.raises(ValueError, match="both positive and negative"):
        train_baseline(labelled, only_benign, manifest, config=BaselineConfig(), seed=7)
