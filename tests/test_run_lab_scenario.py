import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "run_lab_scenario.py"
SPEC = importlib.util.spec_from_file_location("run_lab_scenario", SCRIPT)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


MANIFEST = Path(__file__).parents[1] / "configs" / "lab" / "scenarios.json"


def test_dry_run_prints_steps_without_network(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(runner.urllib.request, "urlopen") as urlopen:
        code = runner.main(
            [
                "--scenario",
                "recon-auth-progression",
                "--manifest",
                str(MANIFEST),
                "--target",
                "idurar-target",
                "--api-key",
                "test-key",
                "--dry-run",
            ]
        )

    assert code == 0
    assert "reconnaissance GET /api/health" in capsys.readouterr().out
    urlopen.assert_not_called()


def test_missing_key_fails_without_network(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(runner.urllib.request, "urlopen") as urlopen:
        code = runner.main(["--scenario", "recon-auth-progression", "--dry-run"])

    assert code == 2
    assert "missing --api-key" in capsys.readouterr().err
    urlopen.assert_not_called()


@pytest.mark.parametrize("target", ["https://example.com", "http://host.docker.internal:8888"])
def test_rejects_external_and_host_targets(target: str) -> None:
    with pytest.raises(ValueError, match="target host is not allowlisted"):
        runner.validate_target(target)


@pytest.mark.parametrize(
    "target", ["http://127.0.0.1:8888", "http://localhost:8888", "http://idurar-target:8888"]
)
def test_allows_loopback_and_compose_target(target: str) -> None:
    assert runner.validate_target(target) == target.rstrip("/")


@pytest.mark.parametrize(
    "target", ["http://127.0.0.1:80", "http://localhost:8080", "http://idurar-target:9999"]
)
def test_rejects_alternate_target_ports(target: str) -> None:
    with pytest.raises(ValueError, match="target port must be 8888"):
        runner.validate_target(target)


@pytest.mark.parametrize("api", ["https://example.com", "http://host.docker.internal:8100"])
def test_rejects_external_and_host_api_targets(api: str) -> None:
    with pytest.raises(ValueError, match="API host is not allowlisted"):
        runner.validate_api(api)


@pytest.mark.parametrize("api", ["http://127.0.0.1:80", "http://localhost:8888", "http://api:9000"])
def test_rejects_alternate_api_ports(api: str) -> None:
    with pytest.raises(ValueError, match="API port must be 8100"):
        runner.validate_api(api)


def test_rejects_scenarios_over_maximum_step_count(tmp_path: Path) -> None:
    step = {"stage": "reconnaissance", "method": "GET", "path": "/api/health"}
    payload = {"scenarios": {"recon-auth-progression": {"steps": [step] * (runner.MAX_STEPS + 1)}}}
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="maximum"):
        runner.load_bounded_scenario(path, "recon-auth-progression")


def test_custom_manifest_is_dry_run_only(tmp_path: Path) -> None:
    path = tmp_path / "scenarios.json"
    path.write_text(
        json.dumps(
            {
                "scenarios": {
                    "recon-auth-progression": {
                        "steps": [
                            {
                                "stage": "reconnaissance",
                                "method": "GET",
                                "path": "/api/health",
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with patch.object(runner.urllib.request, "urlopen") as urlopen:
        assert (
            runner.main(
                [
                    "--scenario",
                    "recon-auth-progression",
                    "--manifest",
                    str(path),
                    "--target",
                    "idurar-target",
                    "--api-key",
                    "test-key",
                ]
            )
            == 2
        )
    urlopen.assert_not_called()

    assert (
        runner.main(
            [
                "--scenario",
                "recon-auth-progression",
                "--manifest",
                str(path),
                "--target",
                "idurar-target",
                "--api-key",
                "test-key",
                "--dry-run",
            ]
        )
        == 0
    )


def test_network_failure_returns_controlled_error(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(runner.urllib.request, "urlopen", side_effect=URLError("offline")):
        code = runner.main(
            [
                "--scenario",
                "recon-auth-progression",
                "--target",
                "idurar-target",
                "--api",
                "api",
                "--api-key",
                "test-key",
            ]
        )

    assert code == 1
    assert "network/API request failed" in capsys.readouterr().err


@pytest.mark.parametrize("status", [401, 403, 404])
def test_expected_application_errors_do_not_abort_step(status: int) -> None:
    scenario = runner.load_scenario(MANIFEST, "recon-auth-progression")
    error = HTTPError("http://idurar-target:8888/api/health", status, "expected", {}, None)
    with patch.object(runner.urllib.request, "urlopen", side_effect=error):
        runner.request_step("http://idurar-target:8888", scenario.steps[0])


def test_builds_unified_event_from_step() -> None:
    scenario = runner.load_scenario(MANIFEST, "recon-auth-progression")
    event = runner.event_for_step("recon-auth-progression", "idurar-target", scenario.steps[0], 0)

    assert event.event_id == "lab:recon-auth-progression:0"
    assert event.event_type == "other"
    assert event.source_entity == "idurar-target"
    assert event.destination_entity == "sentinel-api"
    assert event.features["destination_port"] == 8888.0
    assert event.source_format == "replay"


def test_posts_events_in_bounded_batches() -> None:
    scenario = runner.load_scenario(MANIFEST, "recon-auth-progression")
    events = [
        runner.event_for_step("recon-auth-progression", "idurar-target", step, index)
        for index, step in enumerate(scenario.steps)
    ]
    calls: list[tuple[str, dict, str]] = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, json.loads(request.data), request.get_header("X-api-key")))
        return runner.ResponseStub(b'{"accepted": 2}')

    with patch.object(runner.urllib.request, "urlopen", side_effect=fake_urlopen):
        runner.post_batches("http://api:8100", "test-key", events, batch_size=2)

    assert [len(payload["events"]) for _, payload, _ in calls] == [2, 2]
    assert all(url == "http://api:8100/v1/events" for url, _, _ in calls)
    assert all(key == "test-key" for _, _, key in calls)
