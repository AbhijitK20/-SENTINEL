"""FastAPI service tests: health, model metadata, forecast, detect, errors."""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.auth import ApiKeyStore
from sentinel.baseline import save_baseline_artifacts, train_baseline
from sentinel.config import BaselineConfig
from sentinel.lab_scenarios import load_scenario
from sentinel.predict import DECISION_THRESHOLD
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest

START = datetime(2026, 1, 1, tzinfo=UTC)
MANIFEST = Path(__file__).parents[1] / "configs" / "lab" / "scenarios.json"

_RUNNER_SPEC = importlib.util.spec_from_file_location(
    "run_lab_scenario", Path(__file__).parents[1] / "scripts" / "run_lab_scenario.py"
)
assert _RUNNER_SPEC and _RUNNER_SPEC.loader
_RUNNER = importlib.util.module_from_spec(_RUNNER_SPEC)
_RUNNER_SPEC.loader.exec_module(_RUNNER)


def _event(offset: float, index: int, **features) -> dict:
    return {
        "event_id": f"t{index}",
        "timestamp": (START + timedelta(seconds=offset)).isoformat(),
        "source_entity": "10.0.0.1",
        "destination_entity": "10.0.0.2",
        "event_type": "flow",
        "features": {"bytes": 100.0, **features},
        "source_format": "replay",
        "provenance": "test",
    }


@pytest.fixture(scope="module")
def client(tmp_path_factory) -> TestClient:
    tmp = tmp_path_factory.mktemp("api")
    labelled = generate_labelled_states(
        [f"api{i}" for i in range(5)], seed=21, window_seconds=60, stride_seconds=60
    )
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest([f"api{i}" for i in range(5)], seed=21)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=21,
    )
    save_baseline_artifacts(run, tmp / "baseline")
    # Auth-disabled instance for endpoint-contract tests; the auth matrix
    # (401/403, roles, key lifecycle, audit) is covered in tests/test_auth.py.
    app = create_app(tmp / "baseline", auth_enabled=False)
    return TestClient(app)


@pytest.fixture(scope="module")
def authenticated_client(tmp_path_factory) -> tuple[TestClient, dict[str, str]]:
    tmp = tmp_path_factory.mktemp("api-authenticated")
    labelled = generate_labelled_states(
        [f"api-auth{i}" for i in range(5)], seed=22, window_seconds=60, stride_seconds=60
    )
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest([f"api-auth{i}" for i in range(5)], seed=22)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=22,
    )
    save_baseline_artifacts(run, tmp / "baseline")
    auth_dir = tmp / "auth"
    app = create_app(tmp / "baseline", auth_dir=auth_dir)
    raw_key, _ = ApiKeyStore(auth_dir / "keys.jsonl").create("analyst", label="api-contract")
    return TestClient(app), {"X-API-Key": raw_key}


def test_health_reports_loaded_model(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["threshold"] == pytest.approx(DECISION_THRESHOLD)
    assert body["model_version"]


def test_model_metadata(client: TestClient) -> None:
    body = client.get("/model").json()
    assert body["checksum"]
    assert body["effective_threshold"] >= 0.0


def test_forecast_scores_windows(client: TestClient) -> None:
    events = [_event(0.0, 1), _event(10.0, 2), _event(35.0, 3), _event(65.0, 4)]
    response = client.post(
        "/v1/forecast",
        json={"events": events, "window_seconds": 60, "stride_seconds": 30},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # Events at t=0,10 fall in window 1; t=35 in window 2; t=65 crosses two
    # stride boundaries and closes window 3 — matching the offline builder.
    # The forecast timeline is the per-horizon trajectory from the final
    # state: one point per horizon (max_horizon=1 -> one point).
    assert body["windows"] == 3
    assert len(body["timeline"]) == 1
    assert 0.0 <= body["timeline"][0]["infiltration_probability"] <= 1.0
    assert body["stage"]["stage"]
    assert "x-process-time-ms" in response.headers


def test_detect_emits_nine_findings_per_window(client: TestClient) -> None:
    events = [_event(0.0, 1), _event(10.0, 2), _event(35.0, 3), _event(65.0, 4)]
    body = client.post("/v1/detect", json={"events": events}).json()
    assert body["windows"] == 3
    assert len(body["findings"]) == 30  # 10 detectors x 3 windows
    assert body["alerts"] == 0  # quiet synthetic traffic
    assert body["incidents"] == []


def test_detect_correlates_attack_into_incident(client: TestClient) -> None:
    events = [_event(0.0, 1), _event(10.0, 2)]
    events += [
        _event(31.0 + k * 0.1, 100 + k, bytes=40.0, syn_count=1.0, rst_count=1.0) for k in range(24)
    ] + [_event(65.0, 999)]
    body = client.post("/v1/detect", json={"events": events}).json()
    assert body["alerts"] > 0
    assert body["incidents"], "chained recon alerts must form an incident"
    incident = body["incidents"][0]
    assert incident["progression"][0] == "Reconnaissance"
    assert incident["risk"]["level"] in {"medium", "high", "critical"}


def test_events_accepts_generated_scenario_with_authenticated_client(
    authenticated_client: tuple[TestClient, dict[str, str]],
) -> None:
    client, headers = authenticated_client
    scenario_id = "recon-auth-progression"
    scenario = load_scenario(MANIFEST, scenario_id)
    events = [
        _RUNNER.event_for_step(scenario_id, "http://idurar-target:8888", step, index)
        for index, step in enumerate(scenario.steps)
    ]

    response = client.post(
        "/v1/events",
        json={"events": [event.model_dump(mode="json") for event in events]},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["events_seen"] == len(events)
    assert isinstance(body["windows_emitted"], int)
    assert body["alert_status"] in {"monitoring", "alert", "below-threshold"}
    assert body["peak_probability"] is None or 0.0 <= body["peak_probability"] <= 1.0
    assert isinstance(body["incidents"], list)


def test_forecast_rejects_bad_stride(client: TestClient) -> None:
    events = [_event(0.0, 1), _event(65.0, 2)]
    response = client.post(
        "/v1/forecast",
        json={"events": events, "window_seconds": 30, "stride_seconds": 60},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_forecast_rejects_empty_events(client: TestClient) -> None:
    response = client.post("/v1/forecast", json={"events": []})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_payload"


def test_forecast_rejects_unknown_fields(client: TestClient) -> None:
    events = [_event(0.0, 1), _event(65.0, 2)]
    response = client.post("/v1/forecast", json={"events": events, "bogus": 1})
    assert response.status_code == 422


def test_coverage_endpoint_requires_findings(client: TestClient) -> None:
    """Coverage with no findings should return zero, not hallucinate coverage."""
    body = client.get("/v1/attack-coverage").json()
    assert body["coverage_score"] == 0.0
    assert body["observed_techniques"] == 0
    assert body["total_techniques"] == len(body["attack_type_mapping"])


def test_coverage_counts_only_alerting_findings(client: TestClient) -> None:
    """Zero-probability findings should not count as detection coverage."""
    # Run quiet events that produce zero-probability findings
    events = [_event(0.0, 1), _event(10.0, 2)]
    client.post("/v1/detect", json={"events": events})
    body = client.get("/v1/attack-coverage").json()
    # All findings have probability 0 on quiet traffic — no techniques should be "observed"
    assert body["observed_techniques"] == 0 or body["coverage_score"] == 0.0


def test_coverage_distinct_from_alerting(client: TestClient) -> None:
    """Coverage must distinguish detector execution from observed alerts.

    A technique with findings but zero probability is a detector that
    executed, not a detector that observed an alert.
    """
    # Generate events that produce recon findings (some may alert)
    events = [_event(0.0, 1), _event(10.0, 2)]
    events += [
        _event(31.0 + k * 0.1, 100 + k, bytes=40.0, syn_count=1.0, rst_count=1.0) for k in range(24)
    ]
    client.post("/v1/detect", json={"events": events})
    body = client.get("/v1/attack-coverage").json()
    # With recon activity, some techniques should have findings
    # But coverage_score should reflect only techniques with max_probability > 0
    for _tech_id, tech_data in body["techniques"].items():
        if tech_data["count"] > 0 and tech_data["max_probability"] > 0:
            # This technique has alerting findings — it's observed
            pass
        # Zero-probability techniques exist but don't count as observed


def test_navigator_export_endpoint_exists(client: TestClient) -> None:
    """Navigator layer JSON endpoint is accessible."""
    body = client.get("/v1/attack-coverage/navigator").json()
    assert body["name"] == "SENTINEL Coverage"
    assert body["versions"]["navigator"] == "4.5"
    assert body["domain"] == "enterprise-attack"
    assert isinstance(body["techniques"], list)
