"""Logistic-regression baseline on the current window of a sequence sample.

The baseline is a leakage-safe reference model: it uses the most recent state
in each sample's input window, the same `SequenceSample` builder as the
temporal model, and a `FeatureSchema` fitted only on training states.

Reproducibility guarantees:

- The same `seed` produces the same metrics, weights, model checksum, and
  inference timing.
- The model is trained on the train split and evaluated on the validation
  and test splits that come from a `SplitManifest`.
- The split audit refuses to evaluate a manifest that assigns a scenario to
  more than one split or that fails to assign every sample scenario.
"""

from __future__ import annotations

import hashlib
import io
import platform
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import sklearn.linear_model
from pydantic import BaseModel, ConfigDict, Field

from trajectory.config import BaselineConfig
from trajectory.features import FeatureSchema, fit_feature_schema, vectorize_states
from trajectory.metrics import BinaryMetrics, compute_binary_metrics
from trajectory.schemas import SequenceSample, SplitManifest
from trajectory.targets import LabelledState

MODEL_VERSION = "logistic-regression-baseline-v1"
SPLIT_NAMES = ("train", "validation", "test")


class SplitAudit(BaseModel):
    """Scenario-level isolation check and per-split sample counts."""

    model_config = ConfigDict(extra="forbid")

    sample_counts: dict[str, int]
    positive_counts: dict[str, int]
    scenario_counts: dict[str, int]
    disjoint_scenarios: bool
    disjoint_state_keys: bool
    unassigned_scenarios: list[str] = Field(default_factory=list)


class FeatureWeight(BaseModel):
    """Single logistic-regression coefficient for one standardized feature."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    coefficient: float


class BaselineResult(BaseModel):
    """Serializable result of a single baseline training run."""

    model_config = ConfigDict(extra="forbid")

    model_version: str = MODEL_VERSION
    seed: int = Field(ge=0)
    horizon: int = Field(ge=1)
    config: BaselineConfig
    feature_schema: FeatureSchema
    split_manifest: SplitManifest
    split_audit: SplitAudit
    metrics: dict[str, BinaryMetrics]
    feature_weights: list[FeatureWeight]
    training_seconds: float = Field(ge=0)
    inference_microseconds_per_sample: float = Field(ge=0)
    runtime: dict[str, str]
    model_sha256: str = Field(min_length=64, max_length=64)


@dataclass(frozen=True)
class BaselineRun:
    """In-memory baseline result with a fitted model handle."""

    model: sklearn.linear_model.LogisticRegression
    result: BaselineResult


def audit_split(
    samples: list[SequenceSample] | tuple[SequenceSample, ...],
    manifest: SplitManifest,
) -> SplitAudit:
    """Validate that every sample scenario appears in exactly one split."""
    manifest_scenarios = (
        set(manifest.train_scenarios)
        | set(manifest.validation_scenarios)
        | set(manifest.test_scenarios)
    )
    assigned: dict[str, str] = {}
    duplicates: set[str] = set()
    for name, scenarios in (
        ("train", manifest.train_scenarios),
        ("validation", manifest.validation_scenarios),
        ("test", manifest.test_scenarios),
    ):
        for scenario in scenarios:
            if scenario in assigned:
                duplicates.add(scenario)
            assigned[scenario] = name
    if duplicates:
        raise ValueError(f"scenarios assigned to multiple splits: {sorted(duplicates)}")

    sample_scenarios = {sample.scenario_id for sample in samples}
    unassigned = sorted(sample_scenarios - manifest_scenarios)
    if unassigned:
        raise ValueError(f"scenarios missing from split manifest: {unassigned}")

    sample_counts = {name: 0 for name in SPLIT_NAMES}
    positive_counts = {name: 0 for name in SPLIT_NAMES}
    scenario_counts = {name: 0 for name in SPLIT_NAMES}
    for scenario in manifest_scenarios:
        scenario_counts[assigned[scenario]] += 1
    for sample in samples:
        split = assigned[sample.scenario_id]
        sample_counts[split] += 1
        if sample.target.target_infiltration:
            positive_counts[split] += 1

    state_keys_by_split: dict[str, set[str]] = {name: set() for name in SPLIT_NAMES}
    for sample in samples:
        split = assigned[sample.scenario_id]
        for key in sample.input_state_keys:
            state_keys_by_split[split].add(key)

    seen: set[str] = set()
    disjoint_state_keys = True
    for name in SPLIT_NAMES:
        if state_keys_by_split[name] & seen:
            disjoint_state_keys = False
            break
        seen |= state_keys_by_split[name]

    return SplitAudit(
        sample_counts=sample_counts,
        positive_counts=positive_counts,
        scenario_counts=scenario_counts,
        disjoint_scenarios=len(sample_scenarios) == len(manifest_scenarios),
        disjoint_state_keys=disjoint_state_keys,
        unassigned_scenarios=unassigned,
    )


def train_baseline(
    labelled_states: list[LabelledState] | tuple[LabelledState, ...],
    samples: list[SequenceSample] | tuple[SequenceSample, ...],
    manifest: SplitManifest,
    *,
    config: BaselineConfig,
    seed: int,
) -> BaselineRun:
    """Train a logistic-regression baseline and produce reproducible artifacts."""
    states_by_key = {item.state_key: item for item in labelled_states}
    audit = audit_split(samples, manifest)

    # Reject a manifest that places a scenario in more than one split. The
    # audit already flags duplicates, but we also need to refuse to train on
    # such a manifest.
    manifest_scenarios_per_split = {
        "train": set(manifest.train_scenarios),
        "validation": set(manifest.validation_scenarios),
        "test": set(manifest.test_scenarios),
    }
    for first, scenarios_a in manifest_scenarios_per_split.items():
        for second, scenarios_b in manifest_scenarios_per_split.items():
            if first == second:
                continue
            overlap = scenarios_a & scenarios_b
            if overlap:
                raise ValueError(f"scenarios {sorted(overlap)} appear in multiple splits")

    train_samples = [s for s in samples if s.scenario_id in manifest_scenarios_per_split["train"]]
    if not train_samples:
        raise ValueError("training split contains no samples")
    train_y = np.asarray([float(s.target.target_infiltration) for s in train_samples], dtype=float)
    if len(np.unique(train_y)) < 2:
        raise ValueError("training split must contain both positive and negative samples")

    train_states = [states_by_key[s.input_state_keys[-1]].state for s in train_samples]
    schema = fit_feature_schema(train_states, excluded_features=config.excluded_features)
    train_x = vectorize_states(train_states, schema)

    model, training_seconds = _fit_model(train_x, train_y, config=config, seed=seed)
    metrics, inference_us = _evaluate(samples, states_by_key, schema, model, manifest, config)

    feature_weights = _feature_weights(model, schema)
    model_buffer = io.BytesIO()
    joblib.dump(model, model_buffer)
    checksum = hashlib.sha256(model_buffer.getvalue()).hexdigest()

    horizon = samples[0].target.horizon
    result = BaselineResult(
        seed=seed,
        horizon=horizon,
        config=config,
        feature_schema=schema,
        split_manifest=manifest,
        split_audit=audit,
        metrics=metrics,
        feature_weights=feature_weights,
        training_seconds=training_seconds,
        inference_microseconds_per_sample=inference_us,
        runtime=_runtime_versions(),
        model_sha256=checksum,
    )
    return BaselineRun(model=model, result=result)


def _fit_model(
    x: np.ndarray,
    y: np.ndarray,
    *,
    config: BaselineConfig,
    seed: int,
) -> tuple[sklearn.linear_model.LogisticRegression, float]:
    class_weight = None if config.class_weight == "none" else "balanced"
    model = sklearn.linear_model.LogisticRegression(
        C=config.regularization_c,
        class_weight=class_weight,
        max_iter=config.max_iterations,
        random_state=seed,
        solver="lbfgs",
    )
    started = time.perf_counter()
    model.fit(x, y)
    return model, time.perf_counter() - started


def _evaluate(
    samples: list[SequenceSample] | tuple[SequenceSample, ...],
    states_by_key: dict[str, LabelledState],
    schema: FeatureSchema,
    model: sklearn.linear_model.LogisticRegression,
    manifest: SplitManifest,
    config: BaselineConfig,
) -> tuple[dict[str, BinaryMetrics], float]:
    assignment: dict[str, str] = {}
    for name in SPLIT_NAMES:
        for scenario in getattr(manifest, f"{name}_scenarios"):
            assignment[scenario] = name

    by_split: dict[str, list[SequenceSample]] = {name: [] for name in SPLIT_NAMES}
    for sample in samples:
        by_split[assignment[sample.scenario_id]].append(sample)

    metrics: dict[str, BinaryMetrics] = {}
    inference_total_us = 0.0
    inference_total_samples = 0
    for name, items in by_split.items():
        if not items:
            continue
        xs = np.stack(
            [
                vectorize_states([states_by_key[s.input_state_keys[-1]].state], schema)[0]
                for s in items
            ]
        )
        ys = np.asarray([float(s.target.target_infiltration) for s in items], dtype=float)
        started = time.perf_counter()
        probs = model.predict_proba(xs)[:, 1]
        inference_total_us += (time.perf_counter() - started) * 1_000_000
        inference_total_samples += len(items)
        metrics[name] = compute_binary_metrics(ys, probs, threshold=config.decision_threshold)

    inference_us = inference_total_us / inference_total_samples if inference_total_samples else 0.0
    return metrics, inference_us


def _feature_weights(
    model: sklearn.linear_model.LogisticRegression, schema: FeatureSchema
) -> list[FeatureWeight]:
    coefs = model.coef_[0]
    order = np.argsort(np.abs(coefs))[::-1]
    return [
        FeatureWeight(name=schema.names[index], coefficient=float(coefs[index])) for index in order
    ]


def _runtime_versions() -> dict[str, str]:
    import sklearn

    return {
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
        "numpy": np.__version__,
        "platform": platform.platform(),
    }


def save_baseline_artifacts(run: BaselineRun, output_dir: str | Path) -> dict[str, Path]:
    """Write the JSON result, Markdown report, and pickled model."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "baseline_result.json"
    result_path.write_text(run.result.model_dump_json(indent=2), encoding="utf-8")
    report_path = out / "baseline_report.md"
    report_path.write_text(_render_report(run.result), encoding="utf-8")
    model_path = out / "baseline_model.joblib"
    joblib.dump(run.model, model_path)
    return {"result": result_path, "report": report_path, "model": model_path}


def _render_report(result: BaselineResult) -> str:
    lines = [
        "# Baseline Report",
        "",
        "## Experiment Identity",
        "",
        f"- Feature version: {result.feature_schema.version}",
        "- Split strategy: scenario-held-out (whole scenarios per split)",
        f"- Seed: {result.seed}",
        f"- Model version: {result.model_version}",
        f"- Target: infiltration at horizon +{result.horizon} windows (current window only)",
        f"- Model SHA-256: `{result.model_sha256}`",
        f"- Configuration: `{result.config.model_dump_json()}`",
        "- Runtime: " + ", ".join(f"{k}={v}" for k, v in result.runtime.items()),
        "",
        "## Split Audit",
        "",
        "| Split | Scenarios | Samples | Positives |",
        "|---|---:|---:|---:|",
    ]
    for name in SPLIT_NAMES:
        lines.append(
            f"| {name} | {result.split_audit.scenario_counts.get(name, 0)} | "
            f"{result.split_audit.sample_counts.get(name, 0)} | "
            f"{result.split_audit.positive_counts.get(name, 0)} |"
        )
    lines += [
        "",
        f"- Scenario isolation: {'pass' if result.split_audit.disjoint_scenarios else 'fail'}",
        f"- Window isolation: {'pass' if result.split_audit.disjoint_state_keys else 'fail'}",
        "",
        "## Baseline Metrics",
        "",
        "| Metric | " + " | ".join(name for name in SPLIT_NAMES if name in result.metrics) + " |",
        "|---|" + "---:|" * sum(1 for name in SPLIT_NAMES if name in result.metrics),
    ]
    for label, attr in [
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("F1", "f1"),
        ("False-positive rate", "false_positive_rate"),
        ("PR-AUC", "pr_auc"),
    ]:
        vals = [
            _fmt(getattr(result.metrics[name], attr))
            for name in SPLIT_NAMES
            if name in result.metrics
        ]
        lines.append(f"| {label} | " + " | ".join(vals) + " |")
    lines += [
        "",
        f"- Training time: {result.training_seconds * 1000:.1f} ms",
        f"- Inference latency: {result.inference_microseconds_per_sample:.1f} us/sample",
        "",
        "## Feature Weights (standardized inputs)",
        "",
        "| Feature | Coefficient |",
        "|---|---:|",
    ]
    for weight in result.feature_weights:
        sign = "+" if weight.coefficient >= 0 else ""
        lines.append(f"| {weight.name} | {sign}{weight.coefficient:.4f} |")
    lines += [
        "",
        "## Interpretation",
        "",
        "- `n/a` marks a metric that is undefined for the split (for example, no "
        "positives or no predicted positives); it is not zero.",
        "- The baseline sees one window and cannot express ordering; "
        "it is a reference, not a forecast.",
        "- Results describe the evaluated dataset and split only. "
        "Dataset identity and licensing must be recorded alongside this "
        "report before any external claim.",
        "",
    ]
    return "\n".join(lines)


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"
