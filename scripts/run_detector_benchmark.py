"""Per-detector precision, recall and F1 on held-out windows.

The detector suite has nine rules, and the project could say nothing quantitative
about any of them. `validate_real_detectors.py` reports which rules fire during
the live demo, but that needs docker, a running target, and a single host, and it
yields hit/miss counts rather than metrics. Nothing scored the detectors against
labels on data the model had not seen.

This script does that, and is equally careful about what it *cannot* do. The
synthetic scenario generator labels each window Benign, Reconnaissance, or
Lateral Movement. That gives real ground truth for exactly two of the nine
rules. For the other seven there is no ground truth in this dataset, and a
precision of 0.00 for a detector that can never fire correctly would be a
meaningless number rather than a bad one - so those are reported as
`no_ground_truth` with the reason, not as zeros.

    uv run python scripts/run_detector_benchmark.py

Only the test split of a held-out manifest is scored. Synthetic data, generated
by this run; these numbers describe the generator, not any real network.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinel.detectors import run_all_detectors
from sentinel.synthetic import DATASET_ID, generate_labelled_states
from sentinel.targets import make_split_manifest

DETECTOR_BENCHMARK_VERSION = "detector-benchmark-v2"

# Ground truth this dataset can actually provide, per rule. A rule maps to a
# window label only if the generator produces that label; everything else is
# reported as unevaluable rather than scored against a label it cannot have.
#: The sequence detector reuses real attack_type names, so it must be identifiable.
#: Shared with sentinel.sequence_detector.detect_sequence_prediction.
SEQUENCE_TECHNIQUE = "sequence-prediction"

EVALUABLE: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "lateral_movement": "Lateral Movement",
}

# The rules with no corresponding stage in the synthetic generator, and why.
UNEVALUABLE_REASON: dict[str, str] = {
    "ddos": "the generator contains no volumetric-flood stage to score against",
    "credential_abuse": "no credential-attack stage exists in the generator",
    "exfiltration": "no exfiltration stage exists in the generator",
    "command_and_control": "no beacon or C2 stage exists in the generator",
    "insider_threat": "no insider-behaviour stage exists in the generator",
    "phishing": "no phishing stage exists in the generator",
    "malware_activity": "no malware-delivery stage exists in the generator",
}


@dataclass(frozen=True)
class DetectorScore:
    """One detector's confusion matrix and derived rates on the test split."""

    attack_type: str
    ground_truth: str | None
    evaluable: bool
    reason: str
    windows: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None
    f1: float | None
    alert_rate: float | None


def _rates(tp: int, fp: int, fn: int) -> tuple[float | None, float | None, float | None]:
    """Precision, recall, F1 - ``None`` where the rate is undefined, never 0.0.

    A detector that fired once and was right has recall 1.0 and precision 1.0; a
    detector that never fired has recall 0.0 but *undefined* precision, and
    reporting 0.0 there would read as "it was wrong" rather than "we do not know".
    """
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None or precision + recall == 0:
        f1 = None if precision is None or recall is None else 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return precision, recall, f1


def evaluate_detectors(
    labelled,
    *,
    attack_types: list[str],
) -> list[DetectorScore]:
    """Score every rule over the supplied windows, in window order per scenario."""
    by_scenario: dict[str, list] = {}
    for item in labelled:
        by_scenario.setdefault(item.scenario_id, []).append(item)

    # One pass over the windows, scoring every rule at once.
    counts: dict[str, list[int]] = {name: [0, 0, 0, 0] for name in attack_types}
    alert_counts: dict[str, int] = dict.fromkeys(attack_types, 0)
    window_count = 0
    for scenario_id in sorted(by_scenario):
        states = sorted(by_scenario[scenario_id], key=lambda item: item.state.window_start)
        for index, item in enumerate(states):
            window_count += 1
            history = tuple(s.state for s in states[:index])
            # Only the window-based rules are scored here. `detect_sequence_prediction`
            # reports `attack_type=best_tech`, so it can emit a *second* finding
            # labelled `lateral_movement` on top of the real one. It is a
            # prediction about the next stage drawn from detection history, not a
            # measurement of this window's bytes, and counting it as a detection
            # both inflated recall and pushed the sequence detector's false alarms
            # into the lateral bucket - 31 of them on the test split. Sprint 6 hit
            # the same wall from the other side: the evasion report kept concluding
            # that the lateral alert "arrives as sequence-prediction, not from the
            # byte rule". `mitre_technique` is the discriminator.
            fired = {
                finding.attack_type
                for finding in run_all_detectors(item.state, history)
                if finding.is_alert and finding.mitre_technique != SEQUENCE_TECHNIQUE
            }
            for name in attack_types:
                if name in fired:
                    alert_counts[name] += 1
                stage = EVALUABLE.get(name)
                if stage is None:
                    continue
                truth = item.label.attack_stage == stage
                alerted = name in fired
                if alerted and truth:
                    counts[name][0] += 1
                elif alerted and not truth:
                    counts[name][1] += 1
                elif not alerted and truth:
                    counts[name][2] += 1
                else:
                    counts[name][3] += 1

    scores: list[DetectorScore] = []
    for name in attack_types:
        tp, fp, fn, tn = counts[name]
        precision, recall, f1 = _rates(tp, fp, fn)
        stage = EVALUABLE.get(name)
        scores.append(
            DetectorScore(
                attack_type=name,
                ground_truth=stage,
                evaluable=stage is not None,
                reason=(
                    ""
                    if stage is not None
                    else UNEVALUABLE_REASON.get(name, "no ground-truth label for this rule")
                ),
                windows=window_count,
                true_positive=tp,
                false_positive=fp,
                false_negative=fn,
                true_negative=tn,
                precision=precision,
                recall=recall,
                f1=f1,
                alert_rate=(alert_counts[name] / window_count) if window_count else None,
            )
        )
    return scores


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _render(payload: dict) -> str:
    lines = [
        "# Per-detector benchmark",
        "",
        f"- version: `{payload['benchmark_version']}`",
        f"- dataset: `{payload['dataset_id']}` (**synthetic**, generated by this run)",
        f"- generated: {payload['generated_at']}",
        f"- split scored: `{payload['split']}` ({payload['windows']} windows, "
        f"{payload['scenarios']} scenarios)",
        "",
        "Scored at each rule's own alert threshold, on windows the model was not "
        "trained on. `n/a` means the rate is undefined, not zero.",
        "",
        "| detector | ground truth | TP | FP | FN | TN | precision | recall | F1 | alert rate |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for score in payload["detectors"]:
        lines.append(
            f"| {score['attack_type']} | {score['ground_truth'] or '-'} | "
            f"{score['true_positive']} | {score['false_positive']} | "
            f"{score['false_negative']} | {score['true_negative']} | "
            f"{_fmt(score['precision'])} | {_fmt(score['recall'])} | {_fmt(score['f1'])} | "
            f"{_fmt(score['alert_rate'])} |"
        )
    lines += ["", "## Not evaluable on this dataset", ""]
    unevaluable = [s for s in payload["detectors"] if not s["evaluable"]]
    if unevaluable:
        for score in unevaluable:
            lines.append(f"- **{score['attack_type']}**: {score['reason']}.")
    else:
        lines.append("- none")
    lines += [
        "",
        "A rule with no ground truth here is not a rule that performs badly. It is a "
        "rule this dataset cannot score. `scripts/validate_real_detectors.py` exercises "
        "them against a real target, and its numbers are a plumbing check on a single "
        "host, not a field benchmark.",
        "",
        "## Warnings",
        "",
    ]
    lines += [f"- {warning}" for warning in payload["warnings"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=int, default=12)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--stride-seconds", type=int, default=60)
    parser.add_argument("--output", default="reports/generated/detector-benchmark")
    args = parser.parse_args()

    scenario_ids = [f"db{i:02d}" for i in range(args.scenarios)]
    manifest = make_split_manifest(scenario_ids, seed=args.seed)
    labelled = generate_labelled_states(
        scenario_ids,
        seed=args.seed,
        window_seconds=args.window_seconds,
        stride_seconds=args.stride_seconds,
    )
    test_states = [item for item in labelled if item.scenario_id in manifest.test_scenarios]
    if not test_states:
        raise SystemExit("the split manifest left no test scenarios to score")

    attack_types = sorted(set(EVALUABLE) | set(UNEVALUABLE_REASON))
    scores = evaluate_detectors(test_states, attack_types=attack_types)

    payload = {
        "benchmark_version": DETECTOR_BENCHMARK_VERSION,
        "dataset_id": DATASET_ID,
        "generated_at": datetime.now(UTC).isoformat(),
        "split": "test",
        "scenarios": len(manifest.test_scenarios),
        "windows": len({(item.scenario_id, item.state_key) for item in test_states}),
        "detectors": [asdict(score) for score in scores],
        "warnings": [
            "All figures are from synthetic data generated by this run. They describe "
            "the generator, not any real network, and are not a field benchmark.",
            "Only the reconnaissance and lateral-movement rules have ground truth in "
            "this dataset; the other seven are reported as not evaluable rather than "
            "scored against a label they cannot have.",
        ],
    }
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "detector_benchmark.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out / "detector_benchmark.md").write_text(_render(payload), encoding="utf-8")

    for score in scores:
        if score.evaluable:
            print(
                f"{score.attack_type:<18} precision={_fmt(score.precision)} "
                f"recall={_fmt(score.recall)} f1={_fmt(score.f1)} "
                f"(tp={score.true_positive} fp={score.false_positive} "
                f"fn={score.false_negative})"
            )
    for score in scores:
        if not score.evaluable:
            print(f"{score.attack_type:<18} not evaluable: {score.reason}")
    print(f"windows={payload['windows']} scenarios={payload['scenarios']} split=test")
    for warning in payload["warnings"]:
        print(f"warning: {warning}")
    print(f"detector_benchmark_json={out / 'detector_benchmark.json'}")
    print(f"detector_benchmark_md={out / 'detector_benchmark.md'}")


if __name__ == "__main__":
    main()
