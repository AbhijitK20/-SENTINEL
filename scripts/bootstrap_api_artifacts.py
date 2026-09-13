"""Bootstrap demo-grade baseline artifacts for the API service.

For hosted demos (HF Spaces) where the git-ignored real-benchmark artifacts
are absent. Trains the deterministic synthetic baseline in seconds and saves
it where SENTINEL_ARTIFACTS_DIR expects it. These are pipeline-validation
artifacts, not real-traffic models — the API /model endpoint reports their
version and checksum as usual.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import DECISION_THRESHOLD
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest


def bootstrap(out_dir: Path, *, scenarios: int = 6, seed: int = 17) -> Path:
    labelled = generate_labelled_states(
        [f"api-demo{i}" for i in range(scenarios)],
        seed=seed,
        window_seconds=60,
        stride_seconds=60,
    )
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest([f"api-demo{i}" for i in range(scenarios)], seed=seed)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=seed,
    )
    save_baseline_artifacts(run, out_dir)
    return out_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="/tmp/sentinel-artifacts")
    args = parser.parse_args()
    path = bootstrap(Path(args.out))
    print(f"demo artifacts ready: {path}")
