from pathlib import Path

import yaml

COMPOSE = Path(__file__).parents[1] / "docker-compose.yml"


def test_lab_scenario_runner_is_isolated_and_profile_gated() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = compose["services"]["lab-scenario-runner"]

    assert service["profiles"] == ["lab"]
    assert service["restart"] == "no"
    assert "network_mode" not in service
    assert service.get("privileged") is not True
    assert service["environment"]["SENTINEL_API_KEY"] == "${SENTINEL_API_KEY:-}"
    assert service["command"] == [
        "uv",
        "run",
        "--no-sync",
        "python",
        "scripts/run_lab_scenario.py",
        "--scenario",
        "recon-auth-progression",
        "--manifest",
        "/app/configs/lab/scenarios.json",
        "--target",
        "http://idurar-target:8888",
        "--api",
        "http://api:8100",
    ]
    assert "./configs/lab/scenarios.json:/app/configs/lab/scenarios.json:ro" in service["volumes"]
    assert service["networks"] == ["lab-net"]


def test_lab_network_contains_only_api_and_runner() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert "lab-net" in compose["services"]["api"]["networks"]
    assert compose["services"]["lab-scenario-runner"]["networks"] == ["lab-net"]
    assert compose["networks"]["lab-net"] == {}
    assert "ports" not in compose["services"]["lab-scenario-runner"]


def test_existing_profiles_are_unchanged() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose["services"]

    assert services["prometheus"]["profiles"] == ["obs"]
    assert services["grafana"]["profiles"] == ["obs"]
    assert services["vulnerable-app"]["profiles"] == ["demo"]
    assert services["demo-sentinel"]["profiles"] == ["demo"]
