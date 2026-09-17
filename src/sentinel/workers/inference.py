# SPDX-License-Identifier: Apache-2.0
"""Inference worker for SENTINEL.

Loads trained models from the release bundle and serves predictions.
Falls back to rule-based detection when the model is unavailable.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class InferenceRequest:
    """Inference request."""

    id: str
    features: dict[str, float]
    window_start: str
    window_end: str
    tenant_id: str = ""


@dataclass
class InferenceResponse:
    """Inference response."""

    id: str
    risk_score: float
    stage: str
    stage_probs: dict[str, float]
    degraded: bool = False
    degradation_reason: str = ""
    model_version: str = ""


class InferenceWorker:
    """Inference worker for model serving.

    Loads the release bundle (baseline model + calibration) and serves
    predictions. When the model is unavailable, returns degraded mode
    with explicit reason.
    """

    def __init__(
        self,
        model_dir: str | Path = "models/release/v1",
        batch_size: int = 32,
        max_latency_ms: int = 20,
    ) -> None:
        self.model_dir = Path(model_dir)
        self.batch_size = batch_size
        self.max_latency_ms = max_latency_ms
        self._model: Any = None
        self._calibration: dict[str, Any] = {}
        self._feature_schema: dict[str, Any] = {}
        self._loaded = False
        self._model_version = ""

    def load_model(self) -> bool:
        """Load model from release bundle.

        Returns True if loaded successfully, False otherwise.
        """
        try:
            manifest_path = self.model_dir / "MANIFEST.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(f)
                self._model_version = manifest.get("version", "unknown")

            calibration_path = self.model_dir / "calibration.json"
            if calibration_path.exists():
                with open(calibration_path) as f:
                    self._calibration = json.load(f)

            schema_path = self.model_dir / "feature_schema.json"
            if schema_path.exists():
                with open(schema_path) as f:
                    self._feature_schema = json.load(f)

            # Try to load the baseline model
            model_path = self.model_dir / "baseline_model.joblib"
            if model_path.exists():
                import joblib

                self._model = joblib.load(model_path)
                self._loaded = True
                logger.info("Loaded baseline model from %s", model_path)
                return True

            logger.warning("No model file found in %s", self.model_dir)
            return False

        except Exception as e:
            logger.error("Failed to load model: %s", e)
            return False

    def predict(self, request: InferenceRequest) -> InferenceResponse:
        """Run inference on a single request.

        Uses the loaded model if available, otherwise returns degraded mode.
        """
        if not self._loaded or self._model is None:
            return InferenceResponse(
                id=request.id,
                risk_score=0.0,
                stage="Unknown",
                stage_probs={"Unknown": 1.0},
                degraded=True,
                degradation_reason="Model not loaded — falling back to rule detectors",
                model_version=self._model_version,
            )

        try:
            # Extract features in schema order if available
            feature_names = self._feature_schema.get("features", sorted(request.features.keys()))
            feature_values = [request.features.get(f, 0.0) for f in feature_names]
            features = np.array(feature_values).reshape(1, -1)

            # Get probability from logistic regression
            if hasattr(self._model, "predict_proba"):
                proba = self._model.predict_proba(features)[0]
                risk_score = float(proba[1]) if len(proba) > 1 else float(proba[0])
            else:
                risk_score = float(self._model.predict(features)[0])

            return InferenceResponse(
                id=request.id,
                risk_score=risk_score,
                stage="Unknown",
                stage_probs={"Unknown": 1.0},
                model_version=self._model_version,
            )

        except Exception as e:
            logger.error("Inference failed for %s: %s", request.id, e)
            return InferenceResponse(
                id=request.id,
                risk_score=0.0,
                stage="Unknown",
                stage_probs={"Unknown": 1.0},
                degraded=True,
                degradation_reason=f"Inference error: {e}",
                model_version=self._model_version,
            )

    def predict_batch(self, requests: list[InferenceRequest]) -> list[InferenceResponse]:
        """Run inference on a batch of requests."""
        return [self.predict(req) for req in requests]

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def model_version(self) -> str:
        return self._model_version
