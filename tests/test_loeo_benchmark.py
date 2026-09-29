# SPDX-License-Identifier: Apache-2.0
"""Leave-one-attack-out folds must never train on the stage they are scoring.

The whole value of this benchmark is that the held-out stage is unseen. If a
future edit lets it into training, the number becomes a self-fulfilling
in-sample score that looks great and means nothing - the exact failure the
competitor benchmark ships with (`holdout_stage: null` while claiming "unseen
later attack stages"). So the exclusion is asserted directly, not inferred from
the reported metrics.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

_SPEC = importlib.util.spec_from_file_location(
    "sentinel_loeo_bench",
    Path(__file__).resolve().parents[1] / "scripts" / "run_loeo_benchmark.py",
)
assert _SPEC and _SPEC.loader
loeo = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = loeo
_SPEC.loader.exec_module(loeo)

STAGES = ["Reconnaissance", "Lateral Movement", "Denial of Service"]


def _labelled(stage_of, n=60):
    """Minimal LabelledState-like rows; run_fold only touches .label."""
    from sentinel.schemas import StateLabel

    class Row:
        def __init__(self, stage, idx):
            self.label = StateLabel(
                state_key=f"k{idx}",
                scenario_id="s",
                infiltration=stage != "Benign",
                attack_stage=stage,
                label_source="dataset",
            )

    return [Row(stage_of(i), i) for i in range(n)]


def test_threshold_at_fpr_respects_budget():
    """The chosen cut must actually keep negatives under the FPR budget."""
    rng = np.random.default_rng(0)
    negatives = rng.random(1000) * 0.9
    thr = loeo._threshold_at_fpr(negatives, np.zeros(1000), 0.05)
    assert (negatives >= thr).mean() <= 0.05 + 1e-9


def test_held_out_stage_never_enters_training():
    """Every window of the held-out stage must be absent from fit and calibrate."""
    held = "Lateral Movement"

    # Benign + a second seen attack + the held-out stage. The second attack keeps
    # the training split two-class after the holdout removes `held`.
    def stage_of(i):
        if i < 30:
            return "Benign"
        if i < 60:
            return held
        return "Credential Access"

    labelled = _labelled(stage_of, n=90)
    matrix = np.zeros((len(labelled), 4))
    fold = loeo.run_fold(labelled, None, {"fit": matrix}, held, target_fpr=0.05, seed=42)
    assert fold["status"] == "ok"
    # 90 windows total, 30 held out -> train+calibration is the other 60.
    assert fold["train_windows"] + fold["calibration_windows"] == 60
    assert fold["unseen_stage_windows"] == 30
    assert fold["test_benign_windows"] == 30


@pytest.mark.parametrize("held", STAGES)
def test_fold_scores_absent_stage_without_crashing(held):
    """A stage with no windows in the dataset reports absent, not a fake zero."""
    labelled = _labelled(lambda i: "Benign" if i % 2 else "Credential Access")
    matrix = np.zeros((len(labelled), 4))
    fold = loeo.run_fold(labelled, None, {"fit": matrix}, held, target_fpr=0.05, seed=42)
    assert fold["status"] == "absent_from_dataset"
