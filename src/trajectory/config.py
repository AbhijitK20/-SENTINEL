"""Configuration loading for reproducible local runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    problem_statement: str = Field(pattern=r"^SIH\d+$")
    random_seed: int = Field(ge=0)


class DataConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_seconds: int = Field(gt=0)
    stride_seconds: int = Field(gt=0)
    sequence_length: int = Field(gt=0)
    forecast_horizon: int = Field(gt=0)


class SplitConfig(BaseModel):
    """Scenario-level split fractions; the remainder is the held-out test set."""

    model_config = ConfigDict(extra="forbid")

    train_fraction: float = Field(default=0.6, gt=0, lt=1)
    validation_fraction: float = Field(default=0.2, ge=0, lt=1)

    @model_validator(mode="after")
    def _leaves_test_data(self) -> SplitConfig:
        if self.train_fraction + self.validation_fraction >= 1:
            raise ValueError("train and validation fractions must leave test data")
        return self


class BaselineConfig(BaseModel):
    """Logistic-regression baseline hyperparameters and feature eligibility."""

    model_config = ConfigDict(extra="forbid")

    excluded_features: list[str] = Field(
        default_factory=lambda: ["source_port", "destination_port", "protocol", "tcp_flags"]
    )
    regularization_c: float = Field(default=1.0, gt=0)
    class_weight: Literal["balanced", "none"] = "balanced"
    max_iterations: int = Field(default=1000, gt=0)
    decision_threshold: float = Field(default=0.5, gt=0, lt=1)


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline: str
    temporal: str
    baseline_config: BaselineConfig = Field(default_factory=BaselineConfig)


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    offline: bool = True
    device: str = "cpu"


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: ProjectConfig
    data: DataConfig
    split: SplitConfig = Field(default_factory=SplitConfig)
    model: ModelConfig
    runtime: RuntimeConfig


def load_settings(path: str | Path) -> Settings:
    """Load and validate a YAML configuration file."""
    config_path = Path(path)
    raw: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    return Settings.model_validate(raw)
