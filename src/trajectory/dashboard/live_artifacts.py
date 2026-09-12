"""Artifact selection for the Live tab, by event-source mode.

Extracted from the dashboard script so the precedence logic is importable
(the dashboard itself executes as a Streamlit script and cannot be imported
under bare pytest).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from trajectory.predict import artifacts_from_runs, load_artifacts


def select_live_artifacts(
    *,
    mode: str,
    attack_requested: bool,
    loaded: Any,
    baseline_run: Any,
    reports_dir: Path,
) -> Any:
    """Choose which trained artifacts score the Live tab for this source.

    Precedence (most specific wins):
      1. Local attack demo -> in-memory baseline (transparent spike behaviour).
      2. CSV replay -> saved real-benchmark artifacts when present: they are
         trained on CIC-IDS2017, so real traffic distributions score honestly
         (the synthetic models over-trigger on real features).
      3. Other non-synthetic sources -> saved default artifacts (with temporal
         weights when available).
      4. Fallback -> the in-memory models from this session.
    """
    if attack_requested:
        # The live attack story is scored with the transparent baseline
        # so its observable attack-shaped spike is not smoothed away by
        # the lightweight hosted GRU profile.
        return artifacts_from_runs(baseline_run)

    real_baseline_dir = reports_dir / "real-benchmark" / "baseline"
    real_benchmark_ready = (real_baseline_dir / "baseline_result.json").is_file()
    if mode == "CSV replay" and real_benchmark_ready:
        # Real-traffic replay is scored with the models trained on the
        # CIC-IDS2017 benchmark (REAL_BENCHMARK.md); the synthetic models
        # over-trigger on real feature distributions.
        try:
            return load_artifacts(real_baseline_dir)
        except Exception:  # noqa: BLE001 - fall through to saved defaults
            pass

    if (
        mode != "Synthetic attack replay"
        and (reports_dir / "baseline" / "baseline_result.json").is_file()
    ):
        try:
            temporal_dir = (
                reports_dir / "temporal"
                if (reports_dir / "temporal" / "temporal_result.json").is_file()
                else None
            )
            if temporal_dir is not None or loaded.temporal_result is None:
                return load_artifacts(
                    reports_dir / "baseline",
                    temporal_dir=temporal_dir,
                )
        except Exception:  # noqa: BLE001 - fall back to in-memory models
            return loaded

    return loaded
