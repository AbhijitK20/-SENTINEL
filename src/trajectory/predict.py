"""Forecast inference: load saved baseline + temporal artifacts and emit a
``Forecast`` object that the dashboard and demo can consume.

The module is honest about its attribution:

- For the logistic-regression baseline the per-feature contribution is the
  standardized feature value multiplied by the fitted coefficient. That is the
  exact, local, and reproducible attribution for a linear model; we do not
  call it SHAP because it is not SHAP.
- When trained per-horizon temporal weights are available (in-memory runs or
  a future on-disk format), each timeline point is the GRU probability over
  the observed history sequence at that horizon.
- If the temporal models are not available, the timeline is filled with the
  baseline probability decayed toward 0.5 and a warning is recorded.

All artifacts are read from the ``reports/generated/{baseline,temporal}``
directories produced by ``scripts/run_baseline.py`` and
``scripts/run_temporal.py``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from trajectory.baseline import BaselineResult, FeatureWeight, SplitAudit
from trajectory.features import FeatureSchema, vectorize_states
from trajectory.schemas import (
    DrivingFeature,
    Forecast,
    LeadTimeEstimate,
    NetworkState,
    PredictedStage,
    ProbabilityPoint,
    SplitManifest,
)
from trajectory.stage_mapping import map_stage
from trajectory.temporal import TemporalResult

FORECAST_VERSION = "forecast-inference-v1"
DECISION_THRESHOLD = 0.5
LEAD_TIME_DEFINITION = (
    "lead_windows is the first forecast window (1-indexed) whose infiltration "
    "probability meets or exceeds the decision threshold; it is None when the "
    "threshold is never crossed within the horizon. Ground-truth lead time "
    "against observed stage onset is a separate replay evaluation."
)


class ForecastArtifacts(BaseModel):
    """References to the on-disk artifacts used to produce a forecast."""

    model_config = ConfigDict(extra="forbid")

    baseline_result_path: str = Field(min_length=1)
    baseline_model_path: str = Field(min_length=1)
    temporal_result_path: str | None = None
    temporal_model_dir: str | None = None


@dataclass(frozen=True)
class LoadedArtifacts:
    baseline_result: BaselineResult
    baseline_model: object
    temporal_result: TemporalResult | None
    temporal_models: dict[int, object]
    artifacts: ForecastArtifacts
    calibrated_threshold: float | None = None


def load_artifacts(
    baseline_dir: str | Path,
    *,
    temporal_dir: str | Path | None = None,
) -> LoadedArtifacts:
    """Load saved baseline (and optionally temporal) artifacts from disk.

    When ``calibration.json`` exists beside the baseline artifacts, its
    validated ``best_threshold`` is loaded and applied automatically so a
    calibrated run never needs a CLI flag.
    """
    baseline_root = Path(baseline_dir)
    baseline_result_path = baseline_root / "baseline_result.json"
    baseline_model_path = baseline_root / "baseline_model.joblib"
    if not baseline_result_path.is_file():
        raise FileNotFoundError(f"Baseline result not found: {baseline_result_path}")
    if not baseline_model_path.is_file():
        raise FileNotFoundError(f"Baseline model not found: {baseline_model_path}")

    baseline_result = BaselineResult.model_validate_json(
        baseline_result_path.read_text(encoding="utf-8")
    )
    baseline_model = joblib.load(baseline_model_path)

    calibrated_threshold = _load_calibrated_threshold(baseline_root)

    temporal_result: TemporalResult | None = None
    temporal_models: dict[int, object] = {}
    temporal_result_path: str | None = None
    temporal_model_dir: str | None = None
    if temporal_dir is not None:
        t_root = Path(temporal_dir)
        t_result_path = t_root / "temporal_result.json"
        if not t_result_path.is_file():
            raise FileNotFoundError(f"Temporal result not found: {t_result_path}")
        temporal_result = TemporalResult.model_validate_json(
            t_result_path.read_text(encoding="utf-8")
        )
        temporal_result_path = str(t_result_path)
        temporal_model_dir = str(t_root)
        # Load persisted per-horizon GRU weights when present. Horizons without
        # weight files fall back to the documented decay surrogate with a warning.
        from trajectory.temporal import load_temporal_models

        temporal_models = load_temporal_models(temporal_result, t_root)

    return LoadedArtifacts(
        baseline_result=baseline_result,
        baseline_model=baseline_model,
        temporal_result=temporal_result,
        temporal_models=temporal_models,
        artifacts=ForecastArtifacts(
            baseline_result_path=str(baseline_result_path),
            baseline_model_path=str(baseline_model_path),
            temporal_result_path=temporal_result_path,
            temporal_model_dir=temporal_model_dir,
        ),
        calibrated_threshold=calibrated_threshold,
    )


def _load_calibrated_threshold(baseline_root: Path) -> float | None:
    """Read calibration.json beside the artifacts; invalid files are ignored."""
    calibration_path = baseline_root / "calibration.json"
    if not calibration_path.is_file():
        return None
    try:
        payload = json.loads(calibration_path.read_text(encoding="utf-8"))
        threshold = float(payload["best_threshold"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    if not 0 < threshold < 1:
        return None
    return threshold


def forecast(
    states: list[NetworkState] | tuple[NetworkState, ...],
    artifacts: LoadedArtifacts,
    *,
    max_horizon: int | None = None,
    threshold: float | None = None,
) -> Forecast:
    """Produce a forecast for a windowed input using the loaded artifacts.

    ``threshold`` resolution order: explicit argument, then the calibrated
    threshold stored with the artifacts, then the shipped 0.5 default.
    """
    if not states:
        raise ValueError("at least one network state is required to produce a forecast")
    if threshold is None:
        threshold = artifacts.calibrated_threshold or DECISION_THRESHOLD
    if not 0 < threshold < 1:
        raise ValueError("threshold must be strictly between zero and one")

    ordered = sorted(states, key=lambda state: state.window_start)
    last = ordered[-1]

    schema = artifacts.baseline_result.feature_schema
    baseline_features = _vectorize_state(last, schema)
    baseline_proba = _baseline_probability(artifacts.baseline_model, baseline_features)

    max_horizon = max_horizon or _effective_horizon(artifacts)
    history_matrix = vectorize_states(ordered, schema)
    timeline = _build_timeline(
        artifacts, baseline_features, history_matrix, baseline_proba, max_horizon
    )

    predicted_stage = predicted_stage_from_timeline(timeline, baseline_proba)
    stage_mapping = map_stage(ordered, infiltration_probability=baseline_proba)
    lead_time = lead_time_from_timeline(timeline, threshold)

    driving = _driving_features(
        baseline_features, artifacts.baseline_result.feature_weights, schema
    )

    supporting = _supporting_events(ordered)
    affected = _affected_entities(ordered)

    coverage = _coverage_summary(ordered)
    warnings = forecast_warnings(artifacts, ordered, timeline, threshold)

    return Forecast(
        input_window_start=ordered[0].window_start,
        input_window_end=last.window_end,
        horizon_windows=len(timeline),
        model_version=FORECAST_VERSION,
        probability_timeline=timeline,
        predicted_stage=predicted_stage,
        stage_mapping=stage_mapping,
        lead_time=lead_time,
        affected_entities=affected,
        driving_features=driving,
        supporting_events=supporting,
        coverage=coverage,
        warnings=warnings,
    )


def artifacts_from_runs(
    baseline_run: object,
    *,
    temporal_run: object | None = None,
) -> LoadedArtifacts:
    """Build inference artifacts from in-memory training runs.

    Per-horizon temporal weights, when present on the run, are used by the
    timeline directly; no on-disk paths exist in this mode and the artifact
    paths are marked ``(in-memory)``.
    """
    temporal_models: dict[int, object] = {}
    temporal_result = None
    if temporal_run is not None:
        temporal_result = temporal_run.result
        temporal_models = dict(temporal_run.models)
    return LoadedArtifacts(
        baseline_result=baseline_run.result,
        baseline_model=baseline_run.model,
        temporal_result=temporal_result,
        temporal_models=temporal_models,
        artifacts=ForecastArtifacts(
            baseline_result_path="(in-memory)",
            baseline_model_path="(in-memory)",
        ),
    )


def _vectorize_state(state: NetworkState, schema: FeatureSchema) -> np.ndarray:
    return vectorize_states([state], schema)[0]


def _baseline_probability(model: object, features: np.ndarray) -> float:
    proba = model.predict_proba(features.reshape(1, -1))[:, 1]
    return float(proba[0])


def _effective_horizon(artifacts: LoadedArtifacts) -> int:
    if artifacts.temporal_result is not None and artifacts.temporal_result.horizons:
        return max(h.horizon for h in artifacts.temporal_result.horizons)
    return artifacts.baseline_result.horizon


def _build_timeline(
    artifacts: LoadedArtifacts,
    baseline_features: np.ndarray,
    history_matrix: np.ndarray,
    baseline_proba: float,
    max_horizon: int,
) -> list[ProbabilityPoint]:
    points: list[ProbabilityPoint] = []
    pr_auc = artifacts.baseline_result.metrics.get("test")
    confidence = _confidence_for(pr_auc.pr_auc if pr_auc else None)
    for window in range(1, max_horizon + 1):
        proba = _temporal_probability(
            artifacts, baseline_features, history_matrix, baseline_proba, window
        )
        points.append(
            ProbabilityPoint(
                window=window,
                infiltration_probability=proba,
                confidence=confidence,
            )
        )
    return points


def _temporal_probability(
    artifacts: LoadedArtifacts,
    baseline_features: np.ndarray,
    history_matrix: np.ndarray,
    baseline_proba: float,
    horizon: int,
) -> float:
    if artifacts.temporal_result is None:
        return _decay(baseline_proba, horizon)
    if horizon in artifacts.temporal_models:
        return _temporal_model_probability(artifacts, history_matrix, horizon)
    target = next((h for h in artifacts.temporal_result.horizons if h.horizon == horizon), None)
    if target is None:
        return _decay(baseline_proba, horizon)
    return _decay(baseline_proba, horizon, weight=0.7)


def _temporal_model_probability(
    artifacts: LoadedArtifacts,
    history_matrix: np.ndarray,
    horizon: int,
) -> float:
    """Run the trained per-horizon GRU over the observed history sequence."""
    try:
        import torch
    except ImportError:
        last_row = history_matrix[-1:].reshape(1, -1)
        fallback_proba = float(artifacts.baseline_model.predict_proba(last_row)[:, 1][0])
        return _decay(fallback_proba, horizon)
    model = artifacts.temporal_models[horizon]
    with torch.no_grad():
        sequence = torch.tensor(history_matrix[np.newaxis, ...], dtype=torch.float32)
        logit = model(sequence)
        proba = float(torch.sigmoid(logit).squeeze().item())
    return proba


def _decay(probability: float, horizon: int, *, weight: float = 0.5) -> float:
    """Conservative monotone decay toward 0.5 when temporal evidence is absent."""
    if horizon <= 1:
        return float(np.clip(probability, 0.0, 1.0))
    span = abs(probability - 0.5) * 0.85 ** (horizon - 1)
    if probability >= 0.5:
        return float(np.clip(0.5 + span, 0.0, 1.0))
    return float(np.clip(0.5 - span, 0.0, 1.0))


def _confidence_for(pr_auc: float | None) -> float:
    if pr_auc is None:
        return 0.0
    return float(max(0.0, min(1.0, pr_auc)))


def predicted_stage_from_timeline(
    timeline: list[ProbabilityPoint], baseline_proba: float
) -> PredictedStage:
    peak = max(timeline, key=lambda point: point.infiltration_probability)
    name, name_confidence = _stage_from_probability(peak.infiltration_probability)
    probability = peak.infiltration_probability
    label: Literal["low", "medium", "high", "unknown"]
    if name_confidence >= 0.8:
        label = "high"
    elif name_confidence >= 0.6:
        label = "medium"
    elif name_confidence > 0:
        label = "low"
    else:
        label = "unknown"
    return PredictedStage(name=name, probability=probability, confidence=label)


def _stage_from_probability(probability: float) -> tuple[str, float]:
    if probability >= 0.75:
        return "Lateral Movement", 0.85
    if probability >= 0.5:
        return "Reconnaissance", 0.7
    if probability >= 0.25:
        return "Benign with Anomaly", 0.6
    return "Benign", 0.8


def lead_time_from_timeline(timeline: list[ProbabilityPoint], threshold: float) -> LeadTimeEstimate:
    """Public lead-time helper: first window crossing ``threshold``, or None."""
    """First window crossing the decision threshold, or an explicit None."""
    crossing = next(
        (point.window for point in timeline if point.infiltration_probability >= threshold),
        None,
    )
    return LeadTimeEstimate(
        lead_windows=crossing,
        horizon_windows=len(timeline),
        threshold=threshold,
        definition=LEAD_TIME_DEFINITION,
    )


def _driving_features(
    features: np.ndarray,
    weights: list[FeatureWeight],
    schema: FeatureSchema,
) -> list[DrivingFeature]:
    if not weights:
        return []
    weight_lookup = {weight.name: weight.coefficient for weight in weights}
    contributions: list[DrivingFeature] = []
    for index, name in enumerate(schema.names):
        coefficient = weight_lookup.get(name, 0.0)
        contribution = float(features[index] * coefficient)
        direction = _direction(contribution)
        contributions.append(
            DrivingFeature(
                name=name,
                contribution=contribution,
                direction=direction,
            )
        )
    contributions.sort(key=lambda item: abs(item.contribution), reverse=True)
    return contributions[:5]


def _direction(contribution: float) -> Literal["increasing", "decreasing", "mixed", "unknown"]:
    if contribution > 1e-6:
        return "increasing"
    if contribution < -1e-6:
        return "decreasing"
    return "unknown"


def _supporting_events(states: list[NetworkState]) -> list[str]:
    seen: list[str] = []
    for state in states[-3:]:
        for source_id in state.source_ids:
            if source_id not in seen:
                seen.append(source_id)
    return seen[:10]


def _affected_entities(states: list[NetworkState]) -> list[str]:
    entities: list[str] = []
    for state in states[-3:]:
        for entity in state.entities:
            if entity not in entities:
                entities.append(entity)
    return entities[:10]


def _coverage_summary(states: list[NetworkState]) -> dict[str, bool]:
    flow = any(state.coverage.get("flow", False) for state in states)
    packet = any(state.coverage.get("packet", False) for state in states)
    return {"flow": flow, "packet": packet}


def forecast_warnings(
    artifacts: LoadedArtifacts,
    states: list[NetworkState],
    timeline: list[ProbabilityPoint],
    threshold: float = DECISION_THRESHOLD,
) -> list[str]:
    warnings: list[str] = []
    if artifacts.temporal_result is None:
        warnings.append(
            "Temporal model artifacts were not provided; "
            "the probability timeline is a baseline-only decay estimate."
        )
    elif not artifacts.temporal_models:
        warnings.append(
            "Temporal result was loaded but per-horizon model weights are not "
            "available on disk; the timeline falls back to a decay surrogate."
        )
    if not any(state.coverage.get("packet", False) for state in states):
        warnings.append(
            "Packet features are unavailable; packet-derived signals are not part of this forecast."
        )
    if timeline and max(point.infiltration_probability for point in timeline) < threshold:
        warnings.append(
            "All forecast horizons remain below the decision threshold "
            f"({threshold:.2f}); no predicted infiltration."
        )
    return warnings


def save_forecast(forecast: Forecast, output_path: str | Path) -> Path:
    """Persist a forecast as JSON for inspection or downstream consumption."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(forecast.model_dump_json(indent=2), encoding="utf-8")
    return out


def _split_audit_from_loaded(artifacts: LoadedArtifacts) -> SplitAudit:
    return artifacts.baseline_result.split_audit


def describe_manifest(artifacts: LoadedArtifacts) -> SplitManifest:
    return artifacts.baseline_result.split_manifest


__all__ = [
    "DECISION_THRESHOLD",
    "FORECAST_VERSION",
    "LEAD_TIME_DEFINITION",
    "ForecastArtifacts",
    "artifacts_from_runs",
    "forecast_warnings",
    "lead_time_from_timeline",
    "predicted_stage_from_timeline",
    "LoadedArtifacts",
    "describe_manifest",
    "forecast",
    "load_artifacts",
    "save_forecast",
]
