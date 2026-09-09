from pathlib import Path

from trajectory.config import load_settings


def test_default_config_is_valid() -> None:
    settings = load_settings(Path("configs/default.yaml"))

    assert settings.project.problem_statement == "SIH26153"
    assert settings.data.forecast_horizon == 5
    assert settings.runtime.offline is True
