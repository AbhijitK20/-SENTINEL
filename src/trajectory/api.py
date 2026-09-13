"""FastAPI inference service (roadmap Phase 1): the pipeline over REST.

Loads the same SHA-256-checksummed artifacts as the dashboard and reuses the
live engine's windowing, so REST consumers get results identical to the UI.
Scale level 2 per ROADMAP.md: single-process inference, no auth or
multi-tenancy yet — limitations are stated here, not hidden.

Run: ``uv run uvicorn trajectory.api:create_app --factory --port 8000``
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from trajectory.auth import ApiKeyRecord, ApiKeyStore, AuditLog, role_can
from trajectory.correlation import correlate
from trajectory.detectors import DetectorSet, run_all_detectors
from trajectory.ledger import AlertLedger
from trajectory.predict import DECISION_THRESHOLD, load_artifacts
from trajectory.schemas import Forecast, UnifiedEvent
from trajectory.state_builder import build_network_states

DEFAULT_ASSETS_DIR = Path("reports/generated/real-benchmark/baseline")
DEFAULT_AUTH_DIR = Path("reports/api")


class ForecastRequest(BaseModel):
    """Batch of unified events to window, score, and explain."""

    model_config = ConfigDict(extra="forbid")

    events: list[UnifiedEvent] = Field(min_length=1, max_length=50_000)
    window_seconds: int = Field(default=60, ge=1)
    stride_seconds: int = Field(default=30, ge=1)


class ApiError(BaseModel):
    """Structured error body returned for every handled failure."""

    code: str
    message: str


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": ApiError(code=code, message=message).model_dump()}
    )


class AlertAnchorRequest(BaseModel):
    """A forecast result to anchor into the trust ledger."""

    model_config = ConfigDict(extra="forbid")

    forecast: Forecast


class KeyCreateRequest(BaseModel):
    """Admin payload for issuing a new API key."""

    model_config = ConfigDict(extra="forbid")

    role: str
    label: str = ""
    expires_at: datetime | None = None


def create_app(
    artifacts_dir: str | Path | None = None,
    *,
    threshold: float | None = None,
    auth_enabled: bool = True,
    auth_dir: str | Path | None = None,
) -> FastAPI:
    """Build the API app against one artifacts directory.

    ``threshold=None`` uses the artifact-calibrated threshold, then 0.5 —
    the same resolution chain as every other inference path.
    """
    resolved_dir = Path(artifacts_dir) if artifacts_dir else DEFAULT_ASSETS_DIR
    try:
        artifacts = load_artifacts(resolved_dir)
    except Exception as error:  # noqa: BLE001 - surface at startup, not per request
        raise RuntimeError(f"cannot load artifacts from {resolved_dir}: {error}") from error
    effective_threshold = (
        threshold
        if threshold is not None
        else (artifacts.calibrated_threshold or DECISION_THRESHOLD)
    )
    resolved_auth_dir = Path(auth_dir) if auth_dir else DEFAULT_AUTH_DIR
    keys = ApiKeyStore(resolved_auth_dir / "keys.jsonl") if auth_enabled else None
    audit = AuditLog(resolved_auth_dir / "audit.jsonl") if auth_enabled else None
    ledger = AlertLedger(resolved_auth_dir / "alerts.jsonl")

    app = FastAPI(
        title="SENTINEL Trajectory API",
        version="0.1.0",
        description="Attack-progression forecasting and attack-type detection over unified events.",
    )

    @app.exception_handler(ValidationError)
    async def _validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
        return _error("invalid_payload", str(exc.errors()[:3]), 422)

    @app.exception_handler(RequestValidationError)
    async def _request_validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's built-in body validation uses its own error format;
        # normalize it into the same {"error": {code, message}} contract.
        return _error("invalid_payload", str(exc.errors()[:3]), 422)

    @app.exception_handler(HTTPException)
    async def _http_handler(_: Request, exc: HTTPException) -> JSONResponse:
        code = (
            "unauthorized"
            if exc.status_code == 401
            else "forbidden"
            if exc.status_code == 403
            else "not_found"
            if exc.status_code == 404
            else "bad_request"
        )
        return _error(code, str(exc.detail), exc.status_code)

    def require(method: str, path: str):
        """Auth dependency: resolve the key, then check the permission matrix."""

        def dependency(
            request: Request,
            x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        ) -> ApiKeyRecord | None:
            if keys is None:
                return None
            if not x_api_key:
                raise HTTPException(status_code=401, detail="missing X-API-Key header")
            try:
                record = keys.authenticate(x_api_key)
            except PermissionError as error:
                raise HTTPException(status_code=401, detail=str(error)) from error
            if not role_can(record.role, method, path):
                raise HTTPException(
                    status_code=403,
                    detail=f"role '{record.role}' is not permitted {method} {path}",
                )
            request.state.auth_record = record
            return record

        return Depends(dependency)

    @app.exception_handler(ValueError)
    async def _value_handler(_: Request, exc: ValueError) -> JSONResponse:
        return _error("bad_request", str(exc), 400)

    def _windowed(request: ForecastRequest):
        if request.stride_seconds > request.window_seconds:
            raise ValueError("stride_seconds must not exceed window_seconds")
        ordered = sorted(request.events, key=lambda event: event.timestamp)
        return build_network_states(
            ordered,
            window_seconds=request.window_seconds,
            stride_seconds=request.stride_seconds,
        )

    @app.get("/health")
    def health() -> dict[str, Any]:
        # Public by convention: orchestrator probes do not carry API keys.
        return {
            "status": "ok",
            "artifacts_dir": str(resolved_dir),
            "model_version": artifacts.baseline_result.model_version,
            "threshold": effective_threshold,
            "auth_enabled": auth_enabled,
            "time": datetime.now(UTC).isoformat(),
        }

    @app.get("/model", dependencies=[require("GET", "/model")])
    def model() -> dict[str, Any]:
        baseline = artifacts.baseline_result
        return {
            "model_version": baseline.model_version,
            "checksum": baseline.model_sha256,
            "calibrated_threshold": artifacts.calibrated_threshold,
            "effective_threshold": effective_threshold,
            "horizon": baseline.horizon,
            "feature_schema_version": baseline.feature_schema.version,
            "feature_count": len(baseline.feature_schema.names),
            "metrics_splits": sorted(baseline.metrics.keys()),
        }

    @app.post("/v1/forecast", dependencies=[require("POST", "/v1/forecast")])
    def forecast_endpoint(request: ForecastRequest) -> dict[str, Any]:
        from trajectory.predict import forecast as run_forecast

        states = _windowed(request)
        if not states:
            raise ValueError("no complete windows in the supplied events")
        result = run_forecast(states, artifacts, max_horizon=1, threshold=effective_threshold)
        return {
            "windows": len(states),
            "timeline": [point.model_dump(mode="json") for point in result.probability_timeline],
            "stage": result.stage_mapping.model_dump(mode="json"),
            "driving_features": [f.model_dump(mode="json") for f in result.driving_features],
            "warnings": list(result.warnings),
        }

    @app.post("/v1/detect", dependencies=[require("POST", "/v1/detect")])
    def detect_endpoint(request: ForecastRequest) -> dict[str, Any]:
        states = _windowed(request)
        if not states:
            raise ValueError("no complete windows in the supplied events")
        thresholds = DetectorSet()
        findings = []
        for index, state in enumerate(states):
            history = tuple(states[max(0, index - 6) : index])
            findings.extend(run_all_detectors(state, history, thresholds=thresholds))
        incidents = correlate(tuple(findings))
        return {
            "windows": len(states),
            "findings": [f.model_dump(mode="json") for f in findings],
            "alerts": sum(1 for f in findings if f.is_alert),
            "incidents": [i.model_dump(mode="json") for i in incidents],
        }

    @app.get("/v1/alerts", dependencies=[require("GET", "/v1/alerts")])
    def alerts_list() -> dict[str, Any]:
        records = ledger.records()
        verification = ledger.verify()
        return {
            "count": len(records),
            "verification": verification.model_dump(mode="json"),
            "records": [record.model_dump(mode="json") for record in records[-20:]],
        }

    @app.post("/v1/alerts", dependencies=[require("POST", "/v1/alerts")])
    def alerts_anchor(payload: AlertAnchorRequest) -> dict[str, Any]:
        record = ledger.append_forecast(payload.forecast)
        return {
            "alert_id": record.alert_id,
            "record_hash": record.record_hash,
            "previous_hash": record.previous_hash,
        }

    @app.get("/admin/keys", dependencies=[require("GET", "/admin/keys")])
    def admin_keys_list() -> dict[str, Any]:
        if keys is None:
            raise HTTPException(status_code=409, detail="auth is disabled on this instance")
        return {
            "active": [
                record.model_dump(mode="json", exclude={"key_hash"})
                for record in keys.list_active()
            ]
        }

    @app.post("/admin/keys", dependencies=[require("POST", "/admin/keys")])
    def admin_keys_create(payload: KeyCreateRequest) -> dict[str, Any]:
        if keys is None:
            raise HTTPException(status_code=409, detail="auth is disabled on this instance")
        try:
            raw, record = keys.create(
                payload.role, label=payload.label, expires_at=payload.expires_at
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return {
            "raw_key": raw,
            "key_id": record.key_id,
            "role": record.role,
            "note": (
                "Store this key now — it cannot be retrieved later; only its SHA-256 hash is kept."
            ),
        }

    @app.post("/admin/keys/{key_id}/revoke", dependencies=[require("POST", "/admin/keys")])
    def admin_keys_revoke(key_id: str) -> dict[str, Any]:
        if keys is None:
            raise HTTPException(status_code=409, detail="auth is disabled on this instance")
        if not keys.revoke(key_id):
            raise HTTPException(status_code=404, detail=f"unknown or already-revoked key: {key_id}")
        return {"revoked": key_id}

    @app.middleware("http")
    async def _timing(request: Request, call_next):  # noqa: ANN202 - starlette typing
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["x-process-time-ms"] = f"{elapsed_ms:.1f}"
        if audit is not None and request.url.path != "/health":
            record = getattr(request.state, "auth_record", None)
            audit.record(
                key_id=record.key_id if record else "-",
                role=record.role if record else "anonymous",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                client=request.client.host if request.client else "-",
            )
        return response

    return app


__all__ = ["ApiError", "ForecastRequest", "create_app"]
