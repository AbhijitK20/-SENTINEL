# SPDX-License-Identifier: Apache-2.0
"""Tests for hardening, scale, mlops, ga, observability stub modules."""

from __future__ import annotations

from sentinel.ga.packaging import (
    DockerCompose,
    HelmChart,
    ReleaseArtifact,
    get_docker_compose,
    get_helm_chart,
)
from sentinel.hardening.threat_model import (
    STRIDECategory,
    Threat,
    get_all_threats,
    get_threats_by_category,
    get_threats_by_component,
)
from sentinel.mlops.evaluation_gates import (
    EvaluationGates,
    GateResult,
    GateStatus,
)
from sentinel.mlops.experiment_tracking import (
    ExperimentRun,
    ExperimentTracker,
)
from sentinel.observability.metrics import (
    Metric,
    get_all_metrics,
    get_metric_by_name,
)
from sentinel.scale.capacity import (
    CapacityEstimate,
    CapacityModel,
    estimate_node_count,
    get_capacity_model,
)
from sentinel.security.auth import (
    AuthorizationContext,
    Permission,
    Resource,
    Role,
    Subject,
    check_authorization,
)

# ── Hardening / Threat Model ────────────────────────────────────────────


class TestThreatModel:
    def test_get_all_threats_returns_list(self) -> None:
        threats = get_all_threats()
        assert isinstance(threats, list)
        assert len(threats) > 0

    def test_threat_has_required_fields(self) -> None:
        for threat in get_all_threats():
            assert isinstance(threat, Threat)
            assert threat.component
            assert isinstance(threat.category, STRIDECategory)
            assert threat.description
            assert threat.mitigation
            assert threat.residual_risk

    def test_get_threats_by_component(self) -> None:
        api_threats = get_threats_by_component("API Gateway")
        assert len(api_threats) > 0
        for t in api_threats:
            assert t.component == "API Gateway"

    def test_get_threats_by_category(self) -> None:
        spoofing = get_threats_by_category(STRIDECategory.SPOOFING)
        assert len(spoofing) > 0
        for t in spoofing:
            assert t.category == STRIDECategory.SPOOFING

    def test_all_stride_categories_covered(self) -> None:
        covered = {t.category for t in get_all_threats()}
        for cat in STRIDECategory:
            assert cat in covered, f"Missing STRIDE category: {cat}"


# ── Scale / Capacity ────────────────────────────────────────────────────


class TestCapacity:
    def test_get_capacity_model(self) -> None:
        model = get_capacity_model()
        assert isinstance(model, CapacityModel)
        assert model.node_count == 1
        assert len(model.estimates) > 0

    def test_capacity_estimate_fields(self) -> None:
        for est in get_capacity_model().estimates:
            assert isinstance(est, CapacityEstimate)
            assert est.component
            assert est.events_per_second > 0
            assert est.tenants > 0

    def test_estimate_node_count(self) -> None:
        # Single node should handle at least some events
        nodes = estimate_node_count(1000)
        assert nodes >= 1

    def test_estimate_node_count_scales(self) -> None:
        small = estimate_node_count(1000)
        large = estimate_node_count(1_000_000)
        assert large > small


# ── MLOps / Experiment Tracking ─────────────────────────────────────────


class TestExperimentTracking:
    def test_tracker_log_and_get(self) -> None:
        tracker = ExperimentTracker()
        run = ExperimentRun(
            run_id="run-001",
            git_sha="abc123",
            data_version="v3",
            metrics={"f1": 0.86},
        )
        tracker.log_run(run)
        assert tracker.get_run("run-001") is run
        assert tracker.get_run("nonexistent") is None

    def test_get_runs_by_data_version(self) -> None:
        tracker = ExperimentTracker()
        tracker.log_run(ExperimentRun("r1", "a", "v3"))
        tracker.log_run(ExperimentRun("r2", "b", "v2"))
        tracker.log_run(ExperimentRun("r3", "c", "v3"))
        v3_runs = tracker.get_runs_by_data_version("v3")
        assert len(v3_runs) == 2

    def test_get_latest_run(self) -> None:
        tracker = ExperimentTracker()
        assert tracker.get_latest_run() is None
        r1 = ExperimentRun("r1", "a", "v3")
        r2 = ExperimentRun("r2", "b", "v3")
        tracker.log_run(r1)
        tracker.log_run(r2)
        assert tracker.get_latest_run() is r2


# ── MLOps / Evaluation Gates ────────────────────────────────────────────


class TestEvaluationGates:
    def test_all_passed(self) -> None:
        gates = EvaluationGates()
        gates.add_gate(GateResult("f1", GateStatus.PASS, 0.86, 0.8))
        gates.add_gate(GateResult("fpr", GateStatus.PASS, 0.05, 0.1))
        assert gates.check_all_passed() is True

    def test_one_failure_blocks(self) -> None:
        gates = EvaluationGates()
        gates.add_gate(GateResult("f1", GateStatus.PASS, 0.86, 0.8))
        gates.add_gate(GateResult("fpr", GateStatus.FAIL, 0.15, 0.1))
        assert gates.check_all_passed() is False

    def test_get_failures(self) -> None:
        gates = EvaluationGates()
        gates.add_gate(GateResult("f1", GateStatus.PASS))
        gates.add_gate(GateResult("calibration", GateStatus.FAIL, message="ECE too high"))
        failures = gates.get_failures()
        assert len(failures) == 1
        assert failures[0].name == "calibration"

    def test_to_dict(self) -> None:
        gates = EvaluationGates()
        gates.add_gate(GateResult("f1", GateStatus.PASS))
        result = gates.to_dict()
        assert isinstance(result, list)
        assert result[0]["name"] == "f1"
        assert result[0]["status"] == "pass"


# ── GA / Packaging ──────────────────────────────────────────────────────


class TestPackaging:
    def test_helm_chart(self) -> None:
        chart = get_helm_chart()
        assert isinstance(chart, HelmChart)
        assert chart.name == "sentinel"
        assert chart.version

    def test_docker_compose(self) -> None:
        dc = get_docker_compose()
        assert isinstance(dc, DockerCompose)
        assert len(dc.services) > 0
        assert "sentinel-api" in dc.services

    def test_release_artifact(self) -> None:
        artifact = ReleaseArtifact(
            name="sentinel",
            version="0.1.0",
            sha256="a" * 64,
            signed=True,
            sbom_included=True,
        )
        assert artifact.signed is True
        assert artifact.sbom_included is True


# ── Observability / Metrics ─────────────────────────────────────────────


class TestMetrics:
    def test_get_all_metrics(self) -> None:
        metrics = get_all_metrics()
        assert isinstance(metrics, list)
        assert len(metrics) > 0

    def test_metric_fields(self) -> None:
        for m in get_all_metrics():
            assert isinstance(m, Metric)
            assert m.name
            assert m.description
            assert m.unit
            assert isinstance(m.labels, list)

    def test_get_metric_by_name(self) -> None:
        m = get_metric_by_name("http_requests_total")
        assert m is not None
        assert m.name == "http_requests_total"

    def test_get_metric_by_name_not_found(self) -> None:
        m = get_metric_by_name("nonexistent_metric")
        assert m is None


# ── Security / Auth ─────────────────────────────────────────────────────


class TestSecurityAuth:
    def test_subject_has_permission(self) -> None:
        subject = Subject(id="u1", tenant_id="t1", role=Role.ANALYST)
        assert subject.has_permission(Permission.FORECAST_READ) is True
        assert subject.has_permission(Permission.SYSTEM_ADMIN) is False

    def test_owner_has_all_permissions(self) -> None:
        subject = Subject(id="u1", tenant_id="t1", role=Role.OWNER)
        for perm in Permission:
            assert subject.has_permission(perm) is True

    def test_viewer_limited_permissions(self) -> None:
        subject = Subject(id="u1", tenant_id="t1", role=Role.VIEWER)
        assert subject.has_permission(Permission.FORECAST_READ) is True
        assert subject.has_permission(Permission.CASE_WRITE) is False
        assert subject.has_permission(Permission.MODEL_WRITE) is False

    def test_check_authorization_tenant_mismatch(self) -> None:
        ctx = AuthorizationContext(
            subject=Subject(id="u1", tenant_id="org-a", role=Role.ADMIN),
            resource=Resource(type="forecast", id="f1", tenant_id="org-b"),
            action="read",
        )
        assert check_authorization(ctx) is False

    def test_check_authorization_deny_by_default(self) -> None:
        ctx = AuthorizationContext(
            subject=Subject(id="u1", tenant_id="t1", role=Role.VIEWER),
            resource=Resource(type="forecast", id="f1", tenant_id="t1"),
            action="write",  # viewer cannot write
        )
        assert check_authorization(ctx) is False

    def test_check_authorization_allow(self) -> None:
        ctx = AuthorizationContext(
            subject=Subject(id="u1", tenant_id="t1", role=Role.ANALYST),
            resource=Resource(type="case", id="c1", tenant_id="t1"),
            action="write",
        )
        assert check_authorization(ctx) is True
