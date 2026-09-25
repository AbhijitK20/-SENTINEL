"""The dashboard must boot from the committed release bundle, not retrain.

``models/release/v1`` is a checksummed bundle whose own exporter states "no
training is required to run inference". The dashboard used to ignore it and
``st.stop()`` with "Click Train / Retrain", so every fresh browser session
forced a retrain. These tests pin the bundle-backed boot path.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.dashboard.release import RELEASE_DIR, load_release_runs

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_release_dir_is_the_committed_bundle() -> None:
    assert RELEASE_DIR == REPO_ROOT / "models" / "release" / "v1"
    assert (RELEASE_DIR / "MANIFEST.json").is_file()


def test_load_release_runs_returns_run_shaped_objects() -> None:
    """Downstream code reads ``baseline_run.result`` / ``.model`` and
    ``temporal_run.result.horizons``; the bundle must supply both shapes."""
    runs = load_release_runs()
    assert runs is not None, "committed bundle must load"

    baseline_run, temporal_run, schema = runs
    assert baseline_run.result.model_version
    assert hasattr(baseline_run.model, "predict_proba")
    assert baseline_run.result.feature_schema.width == schema.width
    assert temporal_run.result.horizons, "bundle ships per-horizon GRU results"
    assert len(temporal_run.models) == len(temporal_run.result.horizons)


def test_missing_bundle_returns_none_instead_of_raising() -> None:
    """The app must be able to fall back to prompting for training."""
    assert load_release_runs(RELEASE_DIR / "does-not-exist") is None


def test_corrupt_bundle_returns_none_instead_of_raising() -> None:
    corrupt = REPO_ROOT / "models" / "release" / "v1" / "PROVENANCE.md"
    assert load_release_runs(corrupt) is None, "a file (not a bundle dir) must not raise"


def test_docker_build_keeps_the_release_bundle() -> None:
    """.dockerignore excludes *.joblib and *.pt globally, which would strip the
    bundle's weights on the next image build and silently send the container
    back to retraining. The bundle is the deliverable, so re-include it."""
    patterns = [
        line.strip()
        for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    excluded = {p for p in patterns if not p.startswith("!")}
    assert "*.joblib" in excluded and "*.pt" in excluded, (
        "expected the broad artifact exclusions this test guards against"
    )
    assert any(p.startswith("!") and "models/release" in p for p in patterns), (
        ".dockerignore must re-include models/release so the bundle survives a build"
    )
