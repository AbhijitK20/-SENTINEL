"""The real-data benchmark must never over-claim.

The script's whole value is that its numbers are attributable to CIC-IDS2017.
That only holds if a run against a *stand-in* says so in its own output — a
hardcoded "real-traffic result" string is a lie waiting to be copied into a
submission.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from run_real_benchmark import _claim_status, _dataset_identity, _is_fixture  # noqa: E402

FIXTURE = REPO / "data" / "raw" / "fixture-lab"
REAL = REPO / "data" / "raw" / "cic-ids2017" / "TrafficLabelling"


def test_fixture_directories_are_detected() -> None:
    assert _is_fixture(FIXTURE) is True
    assert _is_fixture(Path("data/raw/synthetic-sample")) is True
    assert _is_fixture(REAL) is False


def test_dataset_identity_names_synthetic_input() -> None:
    identity = _dataset_identity(FIXTURE)
    assert identity.startswith("SYNTHETIC")
    assert "not real traffic" in identity


def test_claim_status_is_derived_not_hardcoded() -> None:
    fixture_claim = _claim_status(FIXTURE)
    real_claim = _claim_status(REAL)

    assert fixture_claim != real_claim
    assert "SYNTHETIC INPUT" in fixture_claim
    assert "NOT a measurement of CIC-IDS2017" in fixture_claim
    assert "real-traffic result on CIC-IDS2017" in real_claim


@pytest.mark.skipif(
    not (REPO / "reports" / "generated" / "real-fixture" / "real_benchmark.json").is_file(),
    reason="run scripts/run_real_benchmark.py --data-dir data/raw/fixture-lab first",
)
def test_generated_fixture_report_disclaims_real_traffic() -> None:
    payload = json.loads(
        (REPO / "reports" / "generated" / "real-fixture" / "real_benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    report = (REPO / "reports" / "generated" / "real-fixture" / "REAL_BENCHMARK.md").read_text(
        encoding="utf-8"
    )

    assert payload["is_synthetic_fixture"] is True
    assert payload["dataset"].startswith("SYNTHETIC")
    assert "SYNTHETIC FIXTURE INPUT" in report
    assert "SYNTHETIC INPUT" in report
    assert "This is a real-traffic result on CIC-IDS2017" not in report


@pytest.mark.skipif(
    not (REPO / "reports" / "generated" / "real-fixture" / "real_benchmark.json").is_file(),
    reason="run scripts/run_real_benchmark.py --data-dir data/raw/fixture-lab first",
)
def test_world_model_is_trained_on_the_real_data_protocol() -> None:
    """The problem statement asks for a learned transition model on real data."""
    payload = json.loads(
        (REPO / "reports" / "generated" / "real-fixture" / "real_benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    world = payload["world_model"]

    assert world["model_version"] == "world-model-rssm-v1"
    assert world["model_sha256"]
    assert world["stage_vocabulary"]
    assert "test" in world["split_metrics"]
    open_loop = world["open_loop_on_test_day"]
    assert open_loop and open_loop["windows"] > 0
    assert len(open_loop["model_mae"]) == len(open_loop["steps"])


@pytest.mark.skipif(
    not (REPO / "reports" / "generated" / "real-fixture" / "real_benchmark.json").is_file(),
    reason="run scripts/run_real_benchmark.py --data-dir data/raw/fixture-lab first",
)
def test_imagination_forecaster_is_scored_on_identical_windows() -> None:
    payload = json.loads(
        (REPO / "reports" / "generated" / "real-fixture" / "real_benchmark.json").read_text(
            encoding="utf-8"
        )
    )
    for evaluation in payload["evaluations"].values():
        assert "imagination" in evaluation
        windows = {evaluation["per_horizon"]["scenarios_evaluated"]}
        windows.add(evaluation["imagination"]["scenarios_evaluated"])
        assert len(windows) == 1, "imagination was scored on a different split"
