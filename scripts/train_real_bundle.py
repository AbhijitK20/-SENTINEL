"""Train and export a release bundle on real CIC-IDS2017, from committed windows.

    uv run python scripts/train_real_bundle.py \
        --derived data/derived/cicids2017_windows.parquet \
        --out models/release/real-cic-v1

**Not shipped.** This trains successfully and writes a valid bundle, but on
measured evidence it is worse than the committed synthetic bundle for the demo:

    real bundle, 32 block scenarios, seed 42: test F1 0.242, recall 0.610, FPR 0.181

CIC-IDS2017 concentrates each attack type in a short window of one day, so even
after subdividing days into contiguous time blocks, test carries only 53 attack
windows across 4 stages and the class balance is poor. That is a property of the
dataset's capture design, not of the trainer - and shipping a weaker bundle as
the default would be a downgrade presented as an improvement.

So the committed bundle stays ``models/release/v1`` (synthetic), and the real
data ships as the *pre-windowed aggregate* in ``data/derived/``, which is where
the real-data value actually is: it loads in 1.6 s, and the real-data detector
measurements in ``research/ATTACK_DETECTION_REAL_DATA.md`` are computed from it.

Run this when you want a real-trained bundle for your own evaluation, or to
re-measure after changing the model. It is not on the demo path.

Reads the pre-windowed aggregate, so it needs neither the 1.2 GB source CSVs nor
the 15-20 minute windowing pass. Re-fitting from source remains possible via
``scripts/run_real_benchmark.py``.

Split discipline is unchanged from the rest of the project: whole scenarios are
assigned to train/validation/test before any window is built, the threshold is
calibrated on validation only, and the deployment baseline is fitted on a
benign reference slice that is disjoint from evaluation.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from sentinel.baseline import save_baseline_artifacts, train_baseline
from sentinel.calibration import calibrate_threshold
from sentinel.config import BaselineConfig
from sentinel.derived import load_derived_windows
from sentinel.detectors import LATERAL_LOOKBACK, fit_deployment_baseline
from sentinel.features import fit_feature_schema, vectorize_states
from sentinel.predict import artifacts_from_runs
from sentinel.targets import build_sequence_samples, make_split_manifest
from sentinel.temporal import TemporalConfig, save_temporal_artifacts, train_temporal
from sentinel.world_model.train import (
    WorldModelConfig,
    save_world_model_artifacts,
    train_world_model,
)

SEED = 42
#: Fraction of train scenarios reserved as the clean reference period for the
#: deployment baseline. The remainder of train is the evaluation baseline pool.
REFERENCE_FRACTION = 0.3


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _known_edge_rates(labelled):
    """Known-edge byte rate per window, matching detect_lateral's own lookback."""
    from sentinel.detectors import _window_seconds

    rates: list[float | None] = []
    for i, item in enumerate(labelled):
        prior = labelled[max(0, i - LATERAL_LOOKBACK) : i]
        if len(prior) < LATERAL_LOOKBACK:
            rates.append(None)
            continue
        seen: set[tuple[str, str]] = set()
        for p in prior:
            seen.update((e["source"], e["destination"]) for e in p.state.edge_summary)
        known = sum(
            e["bytes"] for e in item.state.edge_summary if (e["source"], e["destination"]) in seen
        )
        rates.append(known / _window_seconds(item.state))
    return rates


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--derived", default="data/derived/cicids2017_windows.parquet")
    parser.add_argument("--out", default="models/release/real-cic-v1")
    parser.add_argument("--sequence-length", type=int, default=8)
    parser.add_argument("--horizon", type=int, default=5)
    parser.add_argument("--world-epochs", type=int, default=40)
    parser.add_argument("--core", default="gru", choices=("gru", "lstm", "transformer"))
    parser.add_argument(
        "--scenario-blocks",
        type=int,
        default=4,
        help="contiguous time blocks per day, treated as scenarios for splitting",
    )
    args = parser.parse_args()

    labelled, meta = load_derived_windows(args.derived)
    labelled.sort(key=lambda i: i.state.window_start)
    print(f"loaded {len(labelled):,} real windows ({len(meta.feature_names)} features)")
    print(f"  windowing {meta.window_seconds}s/{meta.stride_seconds}s from {meta.source}")

    # Day-level scenarios are too few: 8 scenarios carrying 7 attack stages cannot
    # be split three ways with every stage represented in train, and the seed
    # search above demonstrated it - a "feasible" split put Credential Access and
    # Initial Access in test only, and test F1 fell to 0.154 because the model
    # had never seen them.
    #
    # So subdivide each day into contiguous time blocks and treat each block as a
    # scenario. Blocks are disjoint in time, so the whole-scenario leakage guard
    # still holds - a test window never shares a scenario with a training window -
    # and 8 scenarios become enough units to balance.
    if args.scenario_blocks > 1:
        by_day: dict[str, list] = {}
        for item in labelled:
            by_day.setdefault(item.scenario_id, []).append(item)
        for items in by_day.values():
            items.sort(key=lambda i: i.state.window_start)
        blocks: list = []
        for day, items in by_day.items():
            per = (len(items) + args.scenario_blocks - 1) // args.scenario_blocks
            for b in range(args.scenario_blocks):
                chunk = items[b * per : (b + 1) * per]
                if not chunk:
                    continue
                # LabelledState is a frozen dataclass, so re-key rather than mutate.
                blocks.extend(
                    dataclasses.replace(item, scenario_id=f"{day}-b{b}") for item in chunk
                )
        labelled = blocks
        print(
            f"  split each day into {args.scenario_blocks} contiguous blocks -> "
            f"{len({i.scenario_id for i in labelled})} scenarios"
        )

    scenario_ids = sorted({i.scenario_id for i in labelled})
    # Stratified by stage, not at random. With 8 scenarios a random split can put
    # a whole attack stage in test only, which trains a bundle that has never seen
    # the stage it is later asked to report.
    # A 3-way *stratified* split is not achievable here: there are 8 scenarios
    # and 7 distinct attack stages, so guaranteeing every stage in every split
    # pushes 7 of 8 scenarios into train and leaves test empty. A bundle with an
    # empty test split reports metrics on nothing, which is worse than an
    # unbalanced one, so use the deterministic seed-based split and report the
    # stage coverage it actually produced rather than implying it was balanced.
    # Seed search for a *feasible* split, not a lucky one. Validation must hold
    # at least one infiltration-positive window, otherwise threshold calibration
    # has no positives to fit on and silently returns the 0.5 default. Reconnaissance
    # windows are infiltration=False by definition, so a Recon-only validation
    # scenario cannot calibrate anything.
    #
    # The search is on feasibility only (non-empty, val and test both contain
    # attacks); it never looks at model performance, so it cannot cherry-pick a
    # flattering split.
    positives = {
        s: sum(1 for i in labelled if i.scenario_id == s and i.label.infiltration)
        for s in scenario_ids
    }
    manifest = None
    chosen_seed = None
    for candidate in range(SEED, SEED + 200):
        trial = make_split_manifest(scenario_ids, seed=candidate)
        if not (trial.train_scenarios and trial.validation_scenarios and trial.test_scenarios):
            continue
        # The split as a whole must hold attacks; individual scenarios need not.
        # A split of benign-only blocks alongside one attack block is perfectly
        # usable, and requiring every block to be an attack made every seed fail.
        if sum(positives[s] for s in trial.validation_scenarios) == 0:
            continue
        if sum(positives[s] for s in trial.test_scenarios) == 0:
            continue
        manifest, chosen_seed = trial, candidate
        break
    if manifest is None:
        raise SystemExit(
            "no feasible split in 200 seeds: with "
            f"{len(scenario_ids)} scenarios and per-scenario attack counts {positives}, "
            "validation and test cannot both hold an attack. Add scenarios, or relax "
            "the requirement that test contain an attack."
        )

    print(f"  split seed {chosen_seed} (feasible: val and test both hold attacks)")
    import collections

    stage_counts: dict[str, collections.Counter] = {
        scenario: collections.Counter() for scenario in scenario_ids
    }
    for item in labelled:
        stage_counts[item.scenario_id][item.label.attack_stage] += 1
    stage_by_scenario = {}
    for scenario, counts in stage_counts.items():
        attacks = [(s, n) for s, n in counts.items() if s != "Benign"]
        stage_by_scenario[scenario] = max(attacks)[0] if attacks else "Benign"

    print(
        f"  scenarios: {len(scenario_ids)} -> {len(manifest.train_scenarios)} train, "
        f"{len(manifest.validation_scenarios)} val, {len(manifest.test_scenarios)} test"
    )
    for split, ids in (
        ("train", manifest.train_scenarios),
        ("val", manifest.validation_scenarios),
        ("test", manifest.test_scenarios),
    ):
        stages = sorted({stage_by_scenario[i] for i in ids})
        benign = sum(
            1 for i in labelled if i.scenario_id in ids and i.label.attack_stage == "Benign"
        )
        attack = sum(1 for i in labelled if i.scenario_id in ids and i.label.infiltration)
        print(
            f"    {split:<5} {benign:>5} benign / {attack:>4} attack  stages: {', '.join(stages)}"
        )

    samples = build_sequence_samples(
        labelled, sequence_length=args.sequence_length, horizon=args.horizon
    )
    if not samples:
        raise SystemExit("no sequence samples; reduce sequence length or horizon")
    print(f"  {len(samples):,} sequence samples")

    schema = fit_feature_schema([i.state for i in labelled])
    print(f"  schema: {schema.width} features")

    print("\ntraining baseline (logistic regression)...")
    baseline_run = train_baseline(labelled, samples, manifest, config=BaselineConfig(), seed=SEED)
    save_baseline_artifacts(baseline_run, args.out)
    metrics = baseline_run.result.metrics.get("test") or next(
        iter(baseline_run.result.metrics.values())
    )
    print(
        f"  test: F1 {metrics.f1:.3f}  recall {metrics.recall:.3f}  "
        f"FPR {metrics.false_positive_rate:.3f}"
    )

    print("calibrating threshold on validation only...")
    val_states = [i for i in labelled if i.scenario_id in manifest.validation_scenarios]
    val_p = baseline_run.model.predict_proba(
        vectorize_states([i.state for i in val_states], schema)
    )[:, 1]
    calibration = calibrate_threshold(
        val_p, [i.label.infiltration for i in val_states], objective="f1"
    )
    (Path(args.out) / "calibration.json").write_text(
        json.dumps(calibration.model_dump(), indent=2) + "\n"
    )
    print(f"  best_threshold {calibration.best_threshold:.3f}")

    print(f"training temporal ({args.core})...")
    temporal_run = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=schema,
        config=TemporalConfig(max_epochs=12),
        seed=SEED,
        max_horizon=args.horizon,
    )
    save_temporal_artifacts(temporal_run, args.out)

    print(f"training world model ({args.core}, {args.world_epochs} epochs)...")
    world_run = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=WorldModelConfig(core_type=args.core, max_epochs=args.world_epochs),
        seed=SEED,
        sequence_length=args.sequence_length,
    )
    save_world_model_artifacts(world_run, args.out)

    # Deployment baseline: a clean, disjoint benign reference from train only.
    train_states = [i for i in labelled if i.scenario_id in manifest.train_scenarios]
    rates = _known_edge_rates(train_states)
    usable = [r for r in rates if r is not None]
    cut = max(1, int(len(usable) * REFERENCE_FRACTION))
    reference = usable[:cut]
    if reference:
        baseline = fit_deployment_baseline(reference)
        (Path(args.out) / "deployment_baseline.json").write_text(
            json.dumps(baseline.model_dump(), indent=2) + "\n"
        )
        print(
            f"deployment baseline: median {baseline.median_bytes_per_sec:.0f} B/s, "
            f"MAD {baseline.mad_bytes_per_sec:.0f}, {baseline.samples} reference windows"
        )
    else:
        print("  WARNING: no usable reference windows; lateral will warn at inference")

    # Manifest, same shape as the synthetic bundle.
    files = sorted(
        p for p in Path(args.out).rglob("*") if p.is_file() and p.name != "MANIFEST.json"
    )
    n_train = len(manifest.train_scenarios)
    n_val = len(manifest.validation_scenarios)
    n_test = len(manifest.test_scenarios)
    (Path(args.out) / "PROVENANCE.md").write_text(
        f"""# Real CIC-IDS2017 release bundle

Trained on **{len(labelled):,} real windows** aggregated from
{meta.source} at {meta.window_seconds}s windows / {meta.stride_seconds}s stride,
read from the committed derived aggregate rather than re-windowing the source.

| | |
|---|---|
| dataset | `{meta.dataset_id}` |
| windows | {len(labelled):,} |
| features | {schema.width} |
| scenarios | {n_train} train / {n_val} val / {n_test} test |
| seed | {SEED} |
| generated | {datetime.now(UTC).isoformat(timespec="seconds")} |

Threshold calibrated on the validation split only. The deployment baseline is
fitted on a benign reference slice of train, disjoint from evaluation.

## Citation

{meta.citation}

Regenerate with `scripts/export_derived_windows.py` then this script.
"""
    )
    manifest_json = {
        "bundle": "real-cic-v1",
        "dataset_id": meta.dataset_id,
        "derived_version": meta.derived_version,
        "windows": len(labelled),
        "features": schema.width,
        "window_seconds": meta.window_seconds,
        "stride_seconds": meta.stride_seconds,
        "seed": SEED,
        "git_sha": _git_sha(),
        "python": platform.python_version(),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "citation": meta.citation,
        "split_stage_coverage": {
            split: sorted({stage_by_scenario[i] for i in ids})
            for split, ids in (
                ("train", manifest.train_scenarios),
                ("validation", manifest.validation_scenarios),
                ("test", manifest.test_scenarios),
            )
        },
        "files": {
            # `size_bytes`, not `bytes`: this is the key both
            # export_release_artifacts.py writes and verify_release_artifacts.py
            # reads. Writing `bytes` here produced a bundle that the project's own
            # integrity check could not read.
            str(p.relative_to(args.out)): {"sha256": _sha256(p), "size_bytes": p.stat().st_size}
            for p in files
        },
    }
    (Path(args.out) / "MANIFEST.json").write_text(json.dumps(manifest_json, indent=2) + "\n")

    total = sum(p.stat().st_size for p in files)
    print(f"\nbundle written to {args.out} ({len(files)} files, {total / 1e6:.2f} MB)")

    # Prove it loads through the public inference path, not just from disk.
    loaded = artifacts_from_runs(baseline_run, temporal_run=temporal_run)
    print(
        f"  artifacts_from_runs ok: {loaded.baseline_result.feature_schema.width} features, "
        f"threshold {loaded.calibrated_threshold}"
    )


if __name__ == "__main__":
    main()
