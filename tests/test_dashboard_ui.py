"""Does the redesigned console actually respond, not just render?

Rendering once proves nothing about a UI. These checks drive the real controls
through Streamlit's own test harness and assert the output changes, which is the
only way to catch a control that is decorative.

The app is expensive to boot (it trains the models), so the painted state is
shared across the read-only checks and only the interaction check pays for a
second run.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "src" / "sentinel" / "dashboard" / "app.py")
TAB_LABELS = [
    "Overview",
    "Forecast",
    "World model",
    "Replay",
    "States",
    "Comparison",
    "Live",
    "Metrics",
    "Demo",
    "Attack story",
]


def _boot() -> AppTest:
    app = AppTest.from_file(APP, default_timeout=900)
    app.run()
    assert not app.exception, app.exception[0].message
    return app


@pytest.fixture(scope="module")
def painted() -> AppTest:
    return _boot()


def _text(app: AppTest) -> str:
    """Everything the user can read: markdown, captions, info, warnings."""
    parts = [element.value for element in app.markdown]
    parts += [element.value for element in app.caption]
    parts += [element.value for element in app.info]
    parts += [element.value for element in app.warning]
    return "\n".join(parts)


def test_app_renders_every_tab_without_error(painted: AppTest) -> None:
    started = time.perf_counter()
    assert [tab.label for tab in painted.tabs] == TAB_LABELS
    body = _text(painted)

    assert "sntl-stat__value" in body, "no stat tiles rendered"
    assert "sntl-panel__title" in body, "no panels rendered"
    assert "sntl-meter__value" in body, "no risk meter rendered"
    assert "sntl-header__mark" in body, "no app header rendered"
    assert time.perf_counter() - started < 600


def test_design_system_css_is_injected_once(painted: AppTest) -> None:
    styles = [m.value for m in painted.markdown if "sentinel-design-system" in m.value]
    assert len(styles) == 1, f"stylesheet injected {len(styles)} times"
    assert "--risk-severe" in styles[0]


def test_scenario_picker_is_labelled_with_its_split(painted: AppTest) -> None:
    """The holdout must be visible where the data is chosen, not buried."""
    pickers = [s for s in painted.selectbox if s.label == "Scenario to forecast from"]
    assert pickers, "scenario picker is missing"
    options = list(pickers[0].options)
    assert options, "scenario picker has no options"
    assert any("test" in option or "train" in option for option in options), options


def test_observed_and_forecast_are_distinguished(painted: AppTest) -> None:
    body = _text(painted)
    assert "sntl-legend__swatch--observed" in body
    assert "sntl-legend__swatch--forecast" in body


def test_world_model_tab_is_opt_in_and_explains_itself(painted: AppTest) -> None:
    assert any(tab.label == "World model" for tab in painted.tabs)
    assert any(c.label == "Train world model" for c in painted.checkbox), (
        "world model tab has no training control"
    )
    assert "imagin" in _text(painted).lower() or "open-loop" in _text(painted).lower()


def test_sidebar_exposes_the_data_source_choice(painted: AppTest) -> None:
    radios = [r for r in painted.radio if r.label == "Dataset"]
    assert radios, "dataset radio missing"
    assert "Synthetic replay" in list(radios[0].options)
    assert any(s.label == "Window (s)" for s in painted.number_input)


def test_a_control_actually_changes_the_screen() -> None:
    """Moving the forecast cut must change what is on screen."""
    app = _boot()
    before = _text(app)
    sliders = [s for s in app.slider if s.label == "Forecast from window"]
    assert sliders, "forecast cut control is missing"
    cut = sliders[0]
    cut.set_value(max(2, cut.value // 2)).run()

    assert not app.exception, app.exception[0].message
    after = _text(app)
    assert after != before, "moving the forecast cut changed nothing on screen"
    assert "Observed through" in after
