# SPDX-License-Identifier: Apache-2.0
"""Contracts and loading for bounded synthetic lab scenarios."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class LabStep(BaseModel):
    """One bounded request and its synthetic telemetry features."""

    model_config = ConfigDict(extra="forbid")

    stage: str = Field(min_length=1)
    method: str = Field(min_length=1)
    path: str = Field(min_length=1)
    features: dict[str, float] = Field(default_factory=dict)


class LabScenario(BaseModel):
    """An ordered synthetic lab scenario."""

    model_config = ConfigDict(extra="forbid")

    steps: list[LabStep]


class LabManifest(BaseModel):
    """Checked-in scenario manifest."""

    model_config = ConfigDict(extra="forbid")

    scenarios: dict[str, LabScenario]


def load_scenario(path: Path, scenario_id: str) -> LabScenario:
    """Load and validate one scenario from a JSON manifest."""

    manifest = LabManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    try:
        return manifest.scenarios[scenario_id]
    except KeyError as exc:
        raise ValueError(f"unknown scenario: {scenario_id}") from exc
