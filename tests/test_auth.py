"""Auth unit tests and the API role/endpoint matrix (roadmap Phase 2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from trajectory.api import create_app
from trajectory.auth import (
    PERMISSIONS,
    ROLES,
    ApiKeyStore,
    AuditLog,
    role_can,
)
from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.predict import DECISION_THRESHOLD
from trajectory.schemas import (
    Forecast,
    PredictedStage,
    ProbabilityPoint,
)
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

# ── store unit tests ─────────────────────────────────────────────────


def test_create_shows_raw_key_once_and_stores_hash(tmp_path) -> None:
    store = ApiKeyStore(tmp_path / "keys.jsonl")
    raw, record = store.create("analyst", label="ci")
    assert raw.startswith("sent_")
    assert record.key_hash != raw
    assert len(record.key_hash) == 64
    assert raw not in (tmp_path / "keys.jsonl").read_text(encoding="utf-8")


def test_create_rejects_unknown_role(tmp_path) -> None:
    store = ApiKeyStore(tmp_path / "keys.jsonl")
    with pytest.raises(ValueError, match="unknown role"):
        store.create("superuser")


def test_revoked_key_cannot_authenticate(tmp_path) -> None:
    store = ApiKeyStore(tmp_path / "keys.jsonl")
    raw, record = store.create("analyst")
    assert store.authenticate(raw).key_id == record.key_id
    assert store.revoke(record.key_id) is True
    with pytest.raises(PermissionError, match="revoked"):
        store.authenticate(raw)
    assert store.revoke(record.key_id) is False


def test_expired_key_cannot_authenticate(tmp_path) -> None:
    store = ApiKeyStore(tmp_path / "keys.jsonl")
    raw, _ = store.create("viewer", expires_at=datetime(2020, 1, 1, tzinfo=UTC))
    with pytest.raises(PermissionError, match="expired"):
        store.authenticate(raw)


def test_naive_expiry_is_treated_as_utc(tmp_path) -> None:
    store = ApiKeyStore(tmp_path / "keys.jsonl")
    raw, _ = store.create("viewer", expires_at=datetime(2020, 1, 1))
    with pytest.raises(PermissionError, match="expired"):
        store.authenticate(raw)


def test_list_active_folds_revocations_and_expiries(tmp_path) -> None:
    store = ApiKeyStore(tmp_path / "keys.jsonl")
    raw1, rec1 = store.create("analyst")
    raw2, rec2 = store.create("viewer", expires_at=datetime(2020, 1, 1))
    raw3, rec3 = store.create("admin")
    store.revoke(rec1.key_id)
    active = {record.key_id for record in store.list_active()}
    assert active == {rec3.key_id}
    assert store.authenticate(raw3).role == "admin"


def test_permission_matrix_is_explicit() -> None:
    assert set(PERMISSIONS) == set(ROLES)
    assert PERMISSIONS["admin"] == ("*",)
    assert role_can("analyst", "POST", "/v1/detect")
    assert not role_can("analyst", "GET", "/admin/keys")
    assert not role_can("viewer", "POST", "/v1/forecast")
    assert role_can("admin", "DELETE", "/anything")


def test_audit_log_is_append_only(tmp_path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.record(
        key_id="sent_x",
        role="admin",
        method="GET",
        path="/model",
        status_code=200,
        client="127.0.0.1",
    )
    audit.record(
        key_id="-",
        role="anonymous",
        method="GET",
        path="/model",
        status_code=401,
        client="127.0.0.1",
    )
    entries = audit.load()
    assert len(entries) == 2
    assert entries[1].status_code == 401


# ── API integration: role/endpoint matrix ────────────────────────────

START = datetime(2026, 1, 1, tzinfo=UTC)


def _forecast() -> Forecast:
    return Forecast(
        input_window_start=START,
        input_window_end=START + timedelta(seconds=60),
        horizon_windows=1,
        model_version="test-model",
        probability_timeline=[
            ProbabilityPoint(window=1, infiltration_probability=0.9, confidence=0.9)
        ],
        predicted_stage=PredictedStage(name="Infiltration", probability=0.9, confidence="high"),
    )


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("auth")
    labelled = generate_labelled_states(
        [f"auth{i}" for i in range(5)], seed=23, window_seconds=60, stride_seconds=60
    )
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest([f"auth{i}" for i in range(5)], seed=23)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=23,
    )
    save_baseline_artifacts(run, tmp / "baseline")
    auth_dir = tmp / "auth"
    app = create_app(tmp / "baseline", auth_dir=auth_dir)
    client = TestClient(app)
    admin_raw, _ = ApiKeyStore(auth_dir / "keys.jsonl").create("admin", label="bootstrap")
    analyst_raw, _ = ApiKeyStore(auth_dir / "keys.jsonl").create("analyst")
    viewer_raw, _ = ApiKeyStore(auth_dir / "keys.jsonl").create("viewer")
    return {
        "client": client,
        "admin": {"X-API-Key": admin_raw},
        "analyst": {"X-API-Key": analyst_raw},
        "viewer": {"X-API-Key": viewer_raw},
        "auth_dir": auth_dir,
        "analyst_raw": analyst_raw,
    }


def test_health_is_public(env) -> None:
    body = env["client"].get("/health").json()
    assert body["status"] == "ok" and body["auth_enabled"] is True


def test_missing_key_is_401_with_structured_error(env) -> None:
    response = env["client"].get("/model")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_garbage_key_is_401(env) -> None:
    response = env["client"].get("/model", headers={"X-API-Key": "sent_nope"})
    assert response.status_code == 401


def test_viewer_cannot_forecast_but_admin_can(env) -> None:
    client = env["client"]
    events = [
        {
            "event_id": "t1",
            "timestamp": START.isoformat(),
            "source_entity": "a",
            "destination_entity": "b",
            "event_type": "flow",
            "features": {"bytes": 100.0},
            "source_format": "replay",
            "provenance": "t",
        }
    ]
    r = client.post("/v1/forecast", json={"events": events}, headers=env["viewer"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    r = client.post(
        "/v1/forecast",
        json={"events": events, "window_seconds": 60, "stride_seconds": 60},
        headers=env["admin"],
    )
    assert r.status_code == 200


def test_analyst_blocked_from_admin_routes(env) -> None:
    response = env["client"].get("/admin/keys", headers=env["analyst"])
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_admin_can_issue_and_revoke_keys(env) -> None:
    client = env["client"]
    body = client.post(
        "/admin/keys",
        json={"role": "engineer", "label": "soc-worker"},
        headers=env["admin"],
    ).json()
    assert body["raw_key"].startswith("sent_")
    engineer = {"X-API-Key": body["raw_key"]}
    assert client.get("/admin/keys", headers=engineer).status_code == 200

    listed = client.get("/admin/keys", headers=env["admin"]).json()["active"]
    assert any(item["role"] == "engineer" for item in listed)
    assert all("key_hash" not in item for item in listed), "hashes must not leak"

    key_id = body["key_id"]
    assert client.post(f"/admin/keys/{key_id}/revoke", headers=env["admin"]).json() == {
        "revoked": key_id
    }
    assert client.get("/admin/keys", headers=engineer).status_code == 401


def test_analyst_can_anchor_alert_and_read_ledger(env) -> None:
    client = env["client"]
    anchored = client.post(
        "/v1/alerts",
        json={"forecast": _forecast().model_dump(mode="json")},
        headers=env["analyst"],
    )
    assert anchored.status_code == 200, anchored.text
    assert anchored.json()["alert_id"].startswith("ALT-")
    listed = client.get("/v1/alerts", headers=env["analyst"]).json()
    assert listed["count"] >= 1
    assert listed["verification"]["valid"] is True


def test_viewer_cannot_anchor_alerts(env) -> None:
    response = env["client"].post(
        "/v1/alerts",
        json={"forecast": _forecast().model_dump(mode="json")},
        headers=env["viewer"],
    )
    assert response.status_code == 403


def test_every_authenticated_request_is_audited(env) -> None:
    audit_entries = AuditLog(env["auth_dir"] / "audit.jsonl").load()
    codes = [(e.method, e.path, e.status_code) for e in audit_entries]
    assert ("GET", "/model", 401) in codes
    assert ("GET", "/admin/keys", 403) in codes
    assert any(e.role == "admin" and e.status_code == 200 for e in audit_entries)
    assert env["analyst_raw"] not in "\n".join(
        line for line in (env["auth_dir"] / "audit.jsonl").read_text().splitlines()
    )
