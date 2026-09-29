from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parents[1]
COMPOSE = REPO_ROOT / "docker-compose.yml"
#: The lab services moved here on 2026-09-29. They build from a sibling
#: repository this one does not contain, and Compose resolves the build context
#: of every profiled service, so leaving them in docker-compose.yml broke
#: `docker compose --profile lab up` on a fresh clone. These tests now assert
#: both that the isolation properties still hold and that the core demo has no
#: unexplained external dependency.
LAB_COMPOSE = Path(__file__).parents[1] / "docker-compose.lab.yml"


def _lab():
    """The effective lab configuration: base file plus the opt-in override."""
    return yaml.safe_load(LAB_COMPOSE.read_text(encoding="utf-8"))


def test_the_core_compose_file_has_no_sibling_repository_dependency() -> None:
    """The default demo must build from a clean clone, with no sibling checkout."""
    text = COMPOSE.read_text(encoding="utf-8")
    assert "idurar-erp-crm" not in text, (
        "docker-compose.yml references a sibling repository; a fresh clone cannot "
        "build it. Lab services belong in docker-compose.lab.yml."
    )
    compose = yaml.safe_load(text)
    for name, service in compose["services"].items():
        build = service.get("build") or {}
        context = build.get("context", "") if isinstance(build, dict) else ""
        assert not str(context).startswith(".."), (
            f"service {name!r} builds from {context!r}, outside this repository"
        )


def test_the_lab_override_documents_the_sibling_dependency() -> None:
    assert LAB_COMPOSE.is_file(), "the lab override file must exist"
    text = LAB_COMPOSE.read_text(encoding="utf-8")
    assert "idurar-erp-crm" in text, (
        "the override must say which sibling repository it needs, and how to use it"
    )
    assert "git clone" in text, "the override must show the clone step"


def test_lab_scenario_runner_is_isolated_and_profile_gated() -> None:
    compose = _lab()
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
    main = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    lab = _lab()
    assert "lab-net" in main["services"]["api"]["networks"]
    assert lab["services"]["lab-scenario-runner"]["networks"] == ["lab-net"]
    # `lab-net` stays declared in the base file, since `api` joins it and the
    # override only adds the lab-only members.
    assert main["networks"]["lab-net"] == {}
    assert "ports" not in lab["services"]["lab-scenario-runner"]


def test_existing_profiles_are_unchanged() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose["services"]

    assert services["prometheus"]["profiles"] == ["obs"]
    assert services["grafana"]["profiles"] == ["obs"]
    assert services["vulnerable-app"]["profiles"] == ["demo"]
    assert services["demo-sentinel"]["profiles"] == ["demo"]


def _split_short_port(spec: str) -> tuple[str, str]:
    """Split a short port mapping into (host_ip, published).

    A short mapping is `host_ip:published:target`, but the host part may itself
    contain colons inside a `${VAR:-default}` expansion, so a plain partition
    splits inside the braces.
    """
    depth = 0
    fields: list[str] = []
    current = ""
    for char in spec:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        if char == ":" and depth == 0:
            fields.append(current)
            current = ""
        else:
            current += char
    fields.append(current)
    if len(fields) == 3:
        return fields[0], fields[1]
    return "", fields[0]


def test_every_published_port_is_loopback_bound() -> None:
    """Nothing in the demo should be reachable from the local network by accident.

    In demo mode the API accepts a published administrative key and the dashboard
    hosts a button that spawns a subprocess. Publishing either on 0.0.0.0 exposes
    that to the LAN. A judge on a laptop reaches both over localhost, which is
    what the loopback default gives, so this costs the demo nothing.

    Set SENTINEL_PUBLISH_HOST=0.0.0.0 to publish deliberately.
    """
    for name in ("docker-compose.yml", "docker-compose.lab.yml"):
        compose = yaml.safe_load((REPO_ROOT / name).read_text(encoding="utf-8"))
        for service, spec in compose.get("services", {}).items():
            for binding in spec.get("ports", []) or []:
                if isinstance(binding, dict):
                    host_ip = binding.get("host_ip")
                    published = binding.get("published")
                else:
                    host_ip, published = _split_short_port(str(binding))
                if not published:
                    continue
                assert host_ip == "${SENTINEL_PUBLISH_HOST:-127.0.0.1}", (
                    f"{name}: service {service!r} publishes {published} on {host_ip!r}; "
                    "every demo port must be loopback-bound by default"
                )


def test_the_attack_runner_gate_reads_the_dashboard_environment() -> None:
    """The env var the gate reads must be on the service that actually runs it.

    `STREAMLIT_SERVER_ADDRESS` was briefly set on the *api* service, which never
    runs Streamlit, so the dashboard inherited 0.0.0.0 from the image ENV and the
    gate blocked the button in Docker while the README implied it worked.
    """
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    dashboard = compose["services"]["dashboard"]
    assert "STREAMLIT_SERVER_ADDRESS" in dashboard.get("environment", {}), (
        "the dashboard must set the address its own attack-runner gate reads"
    )
    assert "STREAMLIT_SERVER_ADDRESS" not in compose["services"]["api"].get("environment", {}), (
        "the API does not run Streamlit; the variable belongs on the dashboard"
    )
