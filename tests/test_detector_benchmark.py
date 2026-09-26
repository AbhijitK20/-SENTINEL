# SPDX-License-Identifier: Apache-2.0
"""A detector benchmark that reports zeros where it should report "cannot tell".

The suite has nine rules and the dataset can score two of them. The failure mode
this guards against is scoring all nine anyway: a precision of 0.00 for a rule
that can never fire correctly reads as "this rule is bad" when the truth is
"this dataset cannot judge it".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "sentinel_detector_bench",
    Path(__file__).resolve().parents[1] / "scripts" / "run_detector_benchmark.py",
)
assert _SPEC and _SPEC.loader
bench = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = bench
_SPEC.loader.exec_module(bench)

SCENARIOS = [f"db{i:02d}" for i in range(12)]


@pytest.fixture(scope="module")
def scores():
    from sentinel.synthetic import generate_labelled_states
    from sentinel.targets import make_split_manifest

    manifest = make_split_manifest(SCENARIOS, seed=42)
    labelled = generate_labelled_states(SCENARIOS, seed=42, window_seconds=60, stride_seconds=60)
    test_states = [i for i in labelled if i.scenario_id in manifest.test_scenarios]
    return bench.evaluate_detectors(
        test_states, attack_types=sorted(set(bench.EVALUABLE) | set(bench.UNEVALUABLE_REASON))
    )


def test_undefined_rates_are_none_not_zero() -> None:
    # tp=0, fp=0: the rule never fired. Precision is undefined, not 0.0.
    precision, recall, f1 = bench._rates(tp=0, fp=0, fn=5)
    assert precision is None
    assert recall == 0.0
    assert f1 is None


def test_a_rule_that_fired_and_was_wrong_is_zero_not_none() -> None:
    precision, recall, f1 = bench._rates(tp=0, fp=4, fn=3)
    assert precision == 0.0
    assert recall == 0.0
    assert f1 == 0.0


def test_a_perfect_rule_scores_one() -> None:
    precision, recall, f1 = bench._rates(tp=5, fp=0, fn=0)
    assert (precision, recall, f1) == (1.0, 1.0, 1.0)


def test_every_rule_is_accounted_for(scores) -> None:
    assert len(scores) == 9
    by_name = {s.attack_type: s for s in scores}
    assert set(by_name) == set(bench.EVALUABLE) | set(bench.UNEVALUABLE_REASON)


def test_rules_without_ground_truth_are_not_scored(scores) -> None:
    by_name = {s.attack_type: s for s in scores}
    for name in bench.UNEVALUABLE_REASON:
        score = by_name[name]
        assert not score.evaluable, f"{name} was scored against a label it cannot have"
        assert score.precision is None
        assert score.recall is None
        assert score.f1 is None
        assert score.reason, f"{name} must say why it is unevaluable"
        # No confusion matrix should have been accumulated for it either.
        assert score.true_positive == score.false_positive == 0
        assert score.false_negative == score.true_negative == 0


def test_the_two_evaluable_rules_get_real_confusion_matrices(scores) -> None:
    by_name = {s.attack_type: s for s in scores}
    for name in bench.EVALUABLE:
        score = by_name[name]
        assert score.evaluable
        assert score.ground_truth == bench.EVALUABLE[name]
        assert score.windows > 0
        assert score.true_positive + score.false_negative > 0, f"{name} had no positives to find"
        total = (
            score.true_positive + score.false_positive + score.false_negative + score.true_negative
        )
        assert total == score.windows


def test_ground_truth_windows_actually_exist(scores) -> None:
    # If a rule has ground truth but the dataset contains none of that stage, the
    # score is vacuous and must not be presented as a result.
    by_name = {s.attack_type: s for s in scores}
    assert by_name["reconnaissance"].true_positive > 0
    assert by_name["lateral_movement"].true_positive > 0


def test_the_report_separates_unevaluable_rules_and_disclaims_the_data() -> None:
    payload = {
        "benchmark_version": bench.DETECTOR_BENCHMARK_VERSION,
        "dataset_id": "synthetic",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "split": "test",
        "scenarios": 3,
        "windows": 100,
        "detectors": [
            {
                "attack_type": "reconnaissance",
                "ground_truth": "Reconnaissance",
                "evaluable": True,
                "reason": "",
                "windows": 100,
                "true_positive": 5,
                "false_positive": 1,
                "false_negative": 0,
                "true_negative": 94,
                "precision": 0.833,
                "recall": 1.0,
                "f1": 0.909,
                "alert_rate": 0.06,
            },
            {
                "attack_type": "ddos",
                "ground_truth": None,
                "evaluable": False,
                "reason": bench.UNEVALUABLE_REASON["ddos"],
                "windows": 100,
                "true_positive": 0,
                "false_positive": 0,
                "false_negative": 0,
                "true_negative": 0,
                "precision": None,
                "recall": None,
                "f1": None,
                "alert_rate": 0.0,
            },
        ],
        "warnings": ["All figures are from synthetic data generated by this run."],
    }
    rendered = bench._render(payload)
    assert "not a field benchmark" in rendered
    assert "synthetic" in rendered
    assert "Not evaluable on this dataset" in rendered
    assert "cannot score" in rendered
    assert "| ddos |" in rendered
    assert "n/a" in rendered
