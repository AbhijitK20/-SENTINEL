"""Run one bounded synthetic lab scenario against the local Idurar service."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sentinel.lab_scenarios import LabStep, load_scenario  # noqa: E402
from sentinel.schemas import UnifiedEvent  # noqa: E402

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "configs" / "lab" / "scenarios.json"
DEFAULT_TARGET = "http://idurar-target:8888"
DEFAULT_API = "http://api:8100"
BATCH_SIZE = 2
MAX_STEPS = 16
ALLOWED_TARGET_HOSTS = {"localhost", "idurar-target"}
ALLOWED_TARGET_IPS = {"127.0.0.1", "::1"}
ALLOWED_API_HOSTS = {"api"}
ALLOWED_SCENARIOS = {"recon-auth-progression"}
ALLOWED_STEPS = {
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/users?search=sentinel-test"),
    ("POST", "/api/uploads/synthetic.txt"),
}


class ResponseStub:
    """Small response context manager used by tests without an HTTP dependency."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> ResponseStub:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def validate_target(target: str) -> str:
    if target in ALLOWED_TARGET_HOSTS:
        return f"http://{target}:8888"
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("target must be an HTTP URL")
    if parsed.hostname not in ALLOWED_TARGET_HOSTS | ALLOWED_TARGET_IPS:
        raise ValueError("target host is not allowlisted")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target must not include a path or query")
    return target.rstrip("/")


def validate_api(api: str) -> str:
    if api == "api":
        return DEFAULT_API
    parsed = urllib.parse.urlparse(api)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("API must be an HTTP URL")
    if parsed.hostname not in ALLOWED_API_HOSTS | ALLOWED_TARGET_IPS:
        raise ValueError("API host is not allowlisted")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("API must not include a path or query")
    return api.rstrip("/")


def load_bounded_scenario(path: Path, scenario_id: str):
    if scenario_id not in ALLOWED_SCENARIOS:
        raise ValueError(f"scenario is not allowlisted: {scenario_id}")
    scenario = load_scenario(path, scenario_id)
    if len(scenario.steps) > MAX_STEPS:
        raise ValueError(f"scenario exceeds maximum of {MAX_STEPS} steps")
    return scenario


def validate_step(step: LabStep) -> None:
    if (step.method, step.path) not in ALLOWED_STEPS:
        raise ValueError(f"scenario step is not allowlisted: {step.method} {step.path}")


def event_for_step(scenario_id: str, target: str, step: LabStep, index: int) -> UnifiedEvent:
    validate_step(step)
    return UnifiedEvent(
        event_id=f"lab:{scenario_id}:{index}",
        timestamp=datetime.now(UTC),
        source_entity=target,
        destination_entity="sentinel-api",
        event_type="other",
        features=dict(step.features),
        source_format="replay",
        provenance=f"lab-scenario:{scenario_id}:{step.stage}",
    )


def request_step(target: str, step: LabStep) -> None:
    validate_step(step)
    data = None
    if step.method == "POST":
        data = json.dumps({"synthetic": True, "scenario": step.stage}).encode("utf-8")
    request = urllib.request.Request(
        f"{target}{step.path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=step.method,
    )
    with urllib.request.urlopen(request, timeout=10):
        pass


def post_batches(
    api: str, api_key: str, events: list[UnifiedEvent], *, batch_size: int = BATCH_SIZE
) -> None:
    for start in range(0, len(events), batch_size):
        batch = events[start : start + batch_size]
        request = urllib.request.Request(
            f"{api.rstrip('/')}/v1/events",
            data=json.dumps(
                {"events": [event.model_dump(mode="json") for event in batch]}
            ).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--target", default=os.environ.get("SENTINEL_LAB_TARGET", DEFAULT_TARGET))
    parser.add_argument("--api", default=os.environ.get("SENTINEL_API_URL", DEFAULT_API))
    parser.add_argument("--api-key", default=os.environ.get("SENTINEL_API_KEY", ""))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not args.api_key:
        print("missing --api-key (or SENTINEL_API_KEY)", file=sys.stderr)
        return 2
    try:
        target = validate_target(args.target)
        api = validate_api(args.api)
        if not args.dry_run and args.manifest.resolve() != DEFAULT_MANIFEST.resolve():
            raise ValueError("custom manifests are allowed only with --dry-run")
        scenario = load_bounded_scenario(args.manifest, args.scenario)
        for step in scenario.steps:
            validate_step(step)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    events = []
    try:
        for index, step in enumerate(scenario.steps):
            print(f"{step.stage} {step.method} {step.path}")
            events.append(event_for_step(args.scenario, target, step, index))
            if not args.dry_run:
                request_step(target, step)
    except (HTTPError, OSError, TimeoutError, URLError) as exc:
        print(f"network/API request failed: {exc}", file=sys.stderr)
        return 1

    if not args.dry_run:
        try:
            post_batches(api, args.api_key, events)
        except (HTTPError, OSError, TimeoutError, URLError) as exc:
            print(f"network/API request failed: {exc}", file=sys.stderr)
            return 1
    print(f"scenario={args.scenario} steps={len(events)} dry_run={args.dry_run}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
