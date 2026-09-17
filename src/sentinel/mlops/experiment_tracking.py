# SPDX-License-Identifier: Apache-2.0
"""Experiment tracking for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ExperimentRun:
    """A single experiment run."""

    run_id: str
    git_sha: str
    data_version: str
    config: dict[str, str] = field(default_factory=dict)
    seed: int = 42
    environment: str = ""
    metrics: dict[str, float] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)


@dataclass
class ExperimentTracker:
    """Experiment tracker for MLOps."""

    runs: list[ExperimentRun] = field(default_factory=list)

    def log_run(self, run: ExperimentRun) -> None:
        """Log an experiment run."""
        self.runs.append(run)

    def get_run(self, run_id: str) -> ExperimentRun | None:
        """Get run by ID."""
        for run in self.runs:
            if run.run_id == run_id:
                return run
        return None

    def get_runs_by_data_version(self, data_version: str) -> list[ExperimentRun]:
        """Get runs by data version."""
        return [r for r in self.runs if r.data_version == data_version]

    def get_latest_run(self) -> ExperimentRun | None:
        """Get the latest run."""
        return self.runs[-1] if self.runs else None
