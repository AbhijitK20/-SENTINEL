"""Tests for the all-phases enterprise sprint (Phases 2-11 scope)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.cases import CaseStore
from sentinel.compliance import generate_report, write_report
from sentinel.drift import band_of, compare_feature, psi
from sentinel.federated import fed_average
from sentinel.feedback import sign_feedback, verify_feedback
from sentinel.registry import ModelRegistry
from sentinel.schemas import AnalystFeedback, NetworkState
from sentinel.synthetic import generate_labelled_states, generate_scenario_events


@pytest.fixture()
def tmp(tmp_path: Path) -> Path:
    return tmp_path


# ── registry ─────────────────────────────────────────────────────────────
def test_registry_promotion_workflow(tmp: Path) -> None:
    reg = ModelRegistry(tmp / "registry.jsonl")
    reg.register(
        "baseline",
        version="v1",
        checksum="abc12345",
        feature_schema_version="sf-v1",
        threshold=0.15,
        training_dataset="synthetic-v1",
    )
    with pytest.raises(ValueError, match="not approved"):
        reg.rollback("baseline", "v1")  # must approve first
    approved = reg.approve("baseline", "v1", approver="ml-team")
    assert approved.status == "approved"
    assert approved.approved_by == "ml-team"
    rolled = reg.rollback("baseline", "v1")
    assert rolled.status == "rolled_back"
    assert reg.latest_status("baseline", "v1").status == "rolled_back"
    assert reg.list_models()[0]["status"] == "rolled_back"


def test_registry_double_approve_rejected(tmp: Path) -> None:
    reg = ModelRegistry(tmp / "registry.jsonl")
    reg.register(
        "m",
        version="v2",
        checksum="abc12345",
        feature_schema_version="sf-v1",
        threshold=0.5,
        training_dataset="d",
    )
    reg.approve("m", "v2", approver="a")
    with pytest.raises(ValueError, match="not registered"):
        reg.approve("m", "v2", approver="a")


# ── drift ────────────────────────────────────────────────────────────────
def test_psi_bands_and_snapshot(tmp: Path) -> None:
    reference = [10.0] * 50 + [20.0] * 50
    assert band_of(psi(reference, list(reference))) == "stable"
    shifted = [10.4] * 20 + [30.0] * 80  # large distribution change
    assert band_of(psi(reference, shifted)) in {"moderate", "significant"}

    from sentinel.drift import DriftSnapshot

    snapshot = DriftSnapshot(tmp / "drift.json")
    snapshot.capture({"bytes": reference})
    reports = snapshot.compare({"bytes": shifted, "unknown_feature": [1.0, 2.0]})
    assert [r.feature for r in reports] == ["bytes"]  # unknown features skipped
    report = compare_feature("bytes", reference, shifted)
    assert report.reference_count == 100
    assert report.current_count == len(shifted)


def test_psi_empty_inputs_are_stable() -> None:
    assert psi([], [1.0, 2.0]) == 0.0
    assert psi([1.0, 2.0], []) == 0.0


# ── cases ────────────────────────────────────────────────────────────────
def test_case_lifecycle_and_sla(tmp: Path) -> None:
    store = CaseStore(tmp / "cases.jsonl")
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    case = store.open_case("INC-001", "critical", assignee="analyst-1", now=t0)
    assert case.sla_due == t0 + timedelta(hours=4)
    store.transition(case.case_id, "ACKNOWLEDGED", actor="a1", now=t0 + timedelta(minutes=10))
    store.transition(case.case_id, "RESOLVED", actor="a1", now=t0 + timedelta(hours=2))
    report = store.sla_report(now=t0 + timedelta(hours=3))
    assert report == {"on_track": 0, "breached": 0, "resolved": 1}
    with pytest.raises(ValueError):
        store.transition(case.case_id, "OPEN")  # resolved is terminal
    with pytest.raises(KeyError):
        store.transition("CASE-9999", "RESOLVED")


def test_case_sla_breach(tmp: Path) -> None:
    store = CaseStore(tmp / "cases.jsonl")
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    case = store.open_case("INC-002", "critical", now=t0)
    report = store.sla_report(now=t0 + timedelta(hours=5))
    assert report["breached"] == 1
    assert store.get(case.case_id).status == "OPEN"


# ── compliance ───────────────────────────────────────────────────────────
def test_compliance_report_is_honest(tmp: Path) -> None:
    report = generate_report()
    assert report.coverage == 0.75
    assert len(report.gaps) == 2
    assert all(gap.status == "gap" for gap in report.gaps)
    assert "MFA" in report.gaps[0].description
    path = write_report(tmp / "compliance" / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "**gap**" in text and "Coverage: 6/8" in text
    assert path.with_suffix(".json").exists()


# ── federated ────────────────────────────────────────────────────────────
def test_fedavg_weighted_average_and_guards() -> None:
    import numpy as np

    from sentinel.federated import ClientUpdate

    updates = [
        ClientUpdate("a", np.array([1.0, 2.0]), 0.5, 100),
        ClientUpdate("b", np.array([3.0, 4.0]), 1.5, 300),
    ]
    result = fed_average(updates)
    assert result.n_clients == 2
    assert result.total_samples == 400
    assert result.coef == pytest.approx([2.5, 3.5])  # (1*100 + 3*300)/400, etc.
    assert result.intercept == pytest.approx(1.25)
    with pytest.raises(ValueError, match="at least one"):
        fed_average([])
    with pytest.raises(ValueError, match="dimensions disagree"):
        fed_average([updates[0], ClientUpdate("c", np.array([1.0]), 0.0, 10)])


def test_fedavg_trains_real_clients() -> None:
    scenarios = [f"fed{i}" for i in range(4)]
    labelled = generate_labelled_states(scenarios, seed=9, window_seconds=60, stride_seconds=60)
    from sentinel.targets import build_sequence_samples, make_split_manifest

    updates = []
    for c in range(2):
        cs = scenarios[c * 2 : (c + 1) * 2]
        cl = [item for item in labelled if item.scenario_id in cs]
        samples = build_sequence_samples(cl, sequence_length=2, horizon=1)
        manifest = make_split_manifest(cs, seed=9)
        from sentinel.federated import train_client

        updates.append(train_client(f"client-{c}", cl, samples, manifest, seed=9))
    result = fed_average(updates)
    assert result.n_clients == 2
    assert result.total_samples == sum(u.n_samples for u in updates)


# ── signed feedback ──────────────────────────────────────────────────────
def test_signed_feedback_detects_tampering() -> None:
    feedback = AnalystFeedback(
        subject_id="INC-001",
        verdict="true_positive",
        analyst="analyst-1",
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    signed = sign_feedback(feedback, b"key-123")
    assert verify_feedback(signed, b"key-123")
    tampered = signed.model_copy(
        update={"feedback": signed.feedback.model_copy(update={"verdict": "false_positive"})}
    )
    assert not verify_feedback(tampered, b"key-123")
    assert not verify_feedback(signed, b"wrong-key")


# ── tenant keys ──────────────────────────────────────────────────────────
def test_api_key_carries_org_id(tmp: Path) -> None:
    from sentinel.auth import ApiKeyStore

    store = ApiKeyStore(tmp / "keys.jsonl")
    raw, record = store.create("analyst", org_id="org-b")
    assert record.org_id == "org-b"
    assert store.authenticate(raw).org_id == "org-b"
    _, default_record = store.create("viewer")
    assert default_record.org_id == "default"


# ── new detectors ────────────────────────────────────────────────────────
def _state(minute: int, features: dict[str, float]) -> NetworkState:
    start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=minute)
    return NetworkState(
        window_start=start,
        window_end=start + timedelta(minutes=1),
        features=features,
        entities=["h1", "h2"],
        edge_summary=[],
        coverage={"flow": True, "packet": False},
        source_ids=[],
    )


BENIGN_FEATURES = {"bytes": 20000.0, "flow_event_count": 8.0}
BENIGN_HISTORY = tuple(_state(i, dict(BENIGN_FEATURES)) for i in range(5))


def test_new_detectors_disabled_without_telemetry() -> None:
    from sentinel.detectors import DetectorSet, run_all_detectors

    findings = run_all_detectors(_state(5, dict(BENIGN_FEATURES)), BENIGN_HISTORY, DetectorSet())
    by_type = {f.attack_type: f for f in findings}
    assert by_type["phishing"].probability == 0.0
    assert any("email telemetry" in w for w in by_type["phishing"].warnings)
    assert by_type["command_and_control"].probability == 0.0
    assert by_type["malware_activity"].probability == 0.0


def test_c2_scores_only_with_beacon_signal() -> None:
    from sentinel.detectors import DetectorSet, detect_c2_beacon

    ctx_hist = BENIGN_HISTORY
    from sentinel.detectors import DetectorContext

    quiet = detect_c2_beacon(
        DetectorContext(
            state=_state(5, {**BENIGN_FEATURES, "c2_beacon_score": 0.1}), history=ctx_hist
        ),
        DetectorSet(),
    )
    assert not quiet.is_alert
    loud = detect_c2_beacon(
        DetectorContext(
            state=_state(5, {**BENIGN_FEATURES, "c2_beacon_score": 0.9}), history=ctx_hist
        ),
        DetectorSet(),
    )
    assert loud.is_alert and loud.probability == 1.0


def test_malware_alerts_on_execution_burst() -> None:
    from sentinel.detectors import DetectorContext, DetectorSet, detect_malware

    burst = detect_malware(
        DetectorContext(
            state=_state(
                5,
                {**BENIGN_FEATURES, "malware_process_executions": 2.0, "event_count": 6.0},
            ),
            history=BENIGN_HISTORY,
        ),
        DetectorSet(),
    )
    assert burst.is_alert and burst.mitre_technique == "T1059"


def test_phishing_scores_dns_surrogate() -> None:
    from sentinel.detectors import DetectorContext, DetectorSet, detect_phishing

    tunnel = detect_phishing(
        DetectorContext(
            state=_state(5, {**BENIGN_FEATURES, "domain_length": 60.0, "dns_tunnel_marker": 1.0}),
            history=BENIGN_HISTORY,
        ),
        DetectorSet(),
    )
    assert tunnel.is_alert
    assert "DNS surrogate" in tunnel.warnings[0]


def test_correlation_includes_new_stages() -> None:
    from sentinel.correlation import PROGRESSION_ORDER, STAGE_NAMES

    for attack_type in ("insider_threat", "phishing", "malware_activity"):
        assert attack_type in PROGRESSION_ORDER
        assert attack_type in STAGE_NAMES


# ── API endpoints ────────────────────────────────────────────────────────
@pytest.fixture()
def api_client(tmp_path: Path):
    """API client against self-trained artifacts — no repo-local state needed
    (the default artifacts dir is git-ignored and absent on CI)."""
    from fastapi.testclient import TestClient

    from sentinel.api import create_app
    from sentinel.auth import ApiKeyStore
    from sentinel.baseline import save_baseline_artifacts, train_baseline
    from sentinel.config import BaselineConfig
    from sentinel.predict import DECISION_THRESHOLD
    from sentinel.targets import build_sequence_samples, make_split_manifest

    scenarios = [f"ent{i}" for i in range(5)]
    labelled = generate_labelled_states(scenarios, seed=31, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(scenarios, seed=31)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=31,
    )
    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(run, baseline_dir)

    auth_dir = tmp_path / "auth"
    app = create_app(baseline_dir, auth_dir=auth_dir)
    client = TestClient(app)
    raw, _ = ApiKeyStore(auth_dir / "keys.jsonl").create("admin")
    return client, {"X-API-Key": raw}


def test_metrics_endpoint_counts_requests(api_client) -> None:
    client, _headers = api_client
    client.get("/health")
    client.get("/metrics")
    body = client.get("/metrics").text
    assert "sentinel_requests_total" in body
    assert 'code="200"' in body
    assert "sentinel_request_latency_ms_count" in body


def test_registry_endpoints_workflow(api_client) -> None:
    client, headers = api_client
    payload = {
        "action": "register",
        "name": "baseline",
        "version": "v1",
        "checksum": "abc12345",
        "feature_schema_version": "sf-v1",
        "threshold": 0.15,
        "training_dataset": "synthetic-v1",
    }
    assert (
        client.post("/v1/registry", headers=headers, json=payload).json()["status"] == "registered"
    )
    approve = client.post(
        "/v1/registry",
        headers=headers,
        json={"action": "approve", "name": "baseline", "version": "v1", "approver": "ml"},
    )
    assert approve.json()["status"] == "approved"
    rollback = client.post(
        "/v1/registry",
        headers=headers,
        json={"action": "rollback", "name": "baseline", "version": "v1"},
    )
    assert rollback.json()["status"] == "rolled_back"
    listing = client.get("/v1/registry", headers=headers).json()
    assert listing["models"][0]["status"] == "rolled_back"


def test_drift_endpoint(api_client) -> None:
    client, headers = api_client
    response = client.post(
        "/v1/drift",
        headers=headers,
        json={
            "feature": "bytes",
            "reference": [10.0] * 50 + [20.0] * 50,
            "current": [10.4] * 20 + [30.0] * 80,
        },
    )
    assert response.status_code == 200
    assert response.json()["band"] in {"moderate", "significant"}


def test_case_endpoints_lifecycle(api_client) -> None:
    client, headers = api_client
    opened = client.post(
        "/v1/cases",
        headers=headers,
        json={"incident_id": "INC-001", "risk_level": "critical", "assignee": "a1"},
    )
    assert opened.status_code == 200
    case_id = opened.json()["case_id"]
    moved = client.post(
        f"/v1/cases/{case_id}/transition", headers=headers, json={"to_status": "ACKNOWLEDGED"}
    )
    assert moved.json()["status"] == "ACKNOWLEDGED"
    listing = client.get("/v1/cases", headers=headers).json()
    assert listing["sla"]["on_track"] == 1


def test_compliance_endpoint_reports_gaps(api_client) -> None:
    client, headers = api_client
    body = client.get("/v1/compliance", headers=headers).json()
    assert body["coverage"] == 0.75
    assert len(body["gaps"]) == 2


def test_events_ingest_through_push_engine(api_client) -> None:
    client, headers = api_client
    events, _meta = generate_scenario_events("hosted-demo", seed=4)
    payload = {"events": [event.model_dump(mode="json") for event in events[:120]]}
    response = client.post("/v1/events", headers=headers, json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["events_seen"] == 120
    assert body["windows_emitted"] >= 1
    assert "incidents" in body


def test_ingest_rejects_empty_batch(api_client) -> None:
    client, headers = api_client
    response = client.post("/v1/events", headers=headers, json={"events": []})
    assert response.status_code == 422
