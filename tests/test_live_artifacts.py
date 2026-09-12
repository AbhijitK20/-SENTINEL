"""Tests for Live-tab artifact selection precedence."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from trajectory.dashboard import live_artifacts
from trajectory.dashboard.live_artifacts import select_live_artifacts

SENTINEL_REAL = object()
SENTINEL_DEFAULT = object()
SENTINEL_ATTACK = object()
LOADED = SimpleNamespace(temporal_result=None)


@pytest.fixture()
def reports_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate the selection logic from the repo's real reports directory."""
    return tmp_path


def _seed_saved(reports: Path) -> None:
    (reports / "baseline").mkdir(parents=True)
    (reports / "baseline" / "baseline_result.json").write_text("{}", encoding="utf-8")


def _seed_real_benchmark(reports: Path) -> None:
    (reports / "real-benchmark" / "baseline").mkdir(parents=True)
    (reports / "real-benchmark" / "baseline" / "baseline_result.json").write_text(
        "{}", encoding="utf-8"
    )


def _select(mode: str, *, attack: bool = False, reports: Path):
    return select_live_artifacts(
        mode=mode,
        attack_requested=attack,
        loaded=LOADED,
        baseline_run=SimpleNamespace(run_id="session"),
        reports_dir=reports,
    )


def test_attack_demo_prefers_in_memory_baseline(reports_dir, monkeypatch):
    monkeypatch.setattr(live_artifacts, "artifacts_from_runs", lambda run: SENTINEL_ATTACK)
    result = _select("Synthetic attack replay", attack=True, reports=reports_dir)
    assert result is SENTINEL_ATTACK


def test_csv_replay_prefers_real_benchmark_artifacts(reports_dir, monkeypatch):
    _seed_real_benchmark(reports_dir)
    monkeypatch.setattr(live_artifacts, "load_artifacts", lambda *_a, **_k: SENTINEL_REAL)
    result = _select("CSV replay", reports=reports_dir)
    assert result is SENTINEL_REAL


def test_csv_replay_falls_back_when_real_benchmark_missing(reports_dir, monkeypatch):
    _seed_saved(reports_dir)
    monkeypatch.setattr(live_artifacts, "load_artifacts", lambda *_a, **_k: SENTINEL_DEFAULT)
    result = _select("CSV replay", reports=reports_dir)
    assert result is SENTINEL_DEFAULT


def test_jsonl_sensor_uses_saved_default_artifacts(reports_dir, monkeypatch):
    _seed_saved(reports_dir)
    monkeypatch.setattr(live_artifacts, "load_artifacts", lambda *_a, **_k: SENTINEL_DEFAULT)
    result = _select("JSONL sensor file", reports=reports_dir)
    assert result is SENTINEL_DEFAULT


def test_synthetic_replay_uses_session_models(reports_dir):
    result = _select("Synthetic attack replay", reports=reports_dir)
    assert result is LOADED
