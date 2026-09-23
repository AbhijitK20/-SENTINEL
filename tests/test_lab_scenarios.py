import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.lab_scenarios import load_scenario


def write_manifest(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_selected_scenario(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        {
            "scenarios": {
                "recon-auth": {
                    "steps": [
                        {
                            "stage": "reconnaissance",
                            "method": "GET",
                            "path": "/api/health",
                            "features": {"request_count": 1.0},
                        }
                    ]
                },
                "other": {"steps": []},
            }
        },
    )

    scenario = load_scenario(path, "recon-auth")

    assert scenario.steps[0].stage == "reconnaissance"
    assert scenario.steps[0].features == {"request_count": 1.0}


def test_rejects_unknown_fields(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        {
            "scenarios": {
                "recon-auth": {
                    "steps": [],
                    "unexpected": True,
                }
            }
        },
    )

    with pytest.raises(ValidationError):
        load_scenario(path, "recon-auth")


def test_rejects_unknown_scenario(tmp_path: Path) -> None:
    path = write_manifest(tmp_path, {"scenarios": {"recon-auth": {"steps": []}}})

    with pytest.raises(ValueError, match="unknown scenario"):
        load_scenario(path, "missing")
