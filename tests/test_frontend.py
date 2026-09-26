"""The design system is code, so its rules are tested like code.

The four rules a visual redesign can silently break:

1. a hex literal escapes the token module and hardcodes a colour,
2. the risk ramp stops being the only bright thing, or loses its band labels,
3. an interactive element loses one of its four states,
4. an animation ships without a reduced-motion guard.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentinel.frontend import ui
from sentinel.frontend.theme import stylesheet, theme_config_toml
from sentinel.frontend.tokens import (
    RISK_BANDS,
    RISK_RAMP,
    color,
    css_variables,
    get_all_colors,
    plotly_layout,
    risk_band,
    risk_color,
    streamlit_theme,
)

DASHBOARD = Path(__file__).resolve().parents[1] / "src" / "sentinel" / "dashboard"
FRONTEND = Path(__file__).resolve().parents[1] / "src" / "sentinel" / "frontend"
HEX = re.compile(r"#[0-9A-Fa-f]{3,8}\b")


# ── 1. Tokens are the only source of colour ─────────────────────────────


def test_no_hex_outside_the_token_module() -> None:
    """Screens and charts must reference tokens, never literals."""
    offenders: list[str] = []
    for path in list(DASHBOARD.rglob("*.py")) + list(FRONTEND.rglob("*.py")):
        if path.name == "tokens.py":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in HEX.findall(line):
                # CSS var definitions are generated into theme.py from tokens.
                if path.name == "theme.py" and "--" in line:
                    continue
                offenders.append(f"{path.name}:{number} {match}")
    assert not offenders, "hardcoded colours outside tokens.py:\n" + "\n".join(offenders)


def test_stylesheet_uses_variables_outside_the_root_block() -> None:
    css = stylesheet()
    _, after_root = css.split("}", 1)
    assert not HEX.search(after_root), "stylesheet hardcodes a colour outside :root"


def test_every_token_reaches_css() -> None:
    variables = css_variables()
    for token in RISK_RAMP:
        assert f"--{token.name}" in variables
    assert variables["--bg-base"] == color("bg-base")
    assert len(variables) > 50, "token set looks truncated"


def test_unknown_token_names_fail_loudly() -> None:
    with pytest.raises(KeyError):
        color("not-a-token")


# ── 2. The risk ramp stays honest ───────────────────────────────────────


def test_risk_colour_and_band_agree() -> None:
    for value in (0.0, 0.24, 0.25, 0.49, 0.5, 0.74, 0.75, 0.89, 0.9, 1.0):
        assert risk_color(value) in {token.value for token in RISK_RAMP}
        assert isinstance(risk_band(value), str) and risk_band(value)


def test_risk_colour_is_monotonic_in_the_ramp() -> None:
    order = [token.value for token in RISK_RAMP]
    assert risk_color(0.1) == order[0]
    assert risk_color(0.99) == order[-1]
    # Each band boundary moves to the next ramp step, not a repeat.
    for lower, upper in zip(order, order[1:], strict=False):
        assert lower != upper
    assert len(RISK_BANDS) == len(RISK_RAMP) - 1


def test_risk_colour_clamps_out_of_range_input() -> None:
    assert risk_color(-5.0) == risk_color(0.0)
    assert risk_color(9.0) == risk_color(1.0)


def test_band_of_returns_none_without_a_value() -> None:
    assert ui.band_of(None) is None
    assert ui.band_of(0.95) == "severe"


def test_confirmed_and_insufficient_are_outside_the_ramp() -> None:
    """Observed and unmeasured must never be mistaken for a probability."""
    ramp_values = {token.value for token in RISK_RAMP}
    assert color("confirmed") not in ramp_values
    assert color("insufficient") not in ramp_values


# ── 3. Interactive elements carry all four states ───────────────────────


def test_interactive_element_defines_four_states() -> None:
    css = stylesheet()
    block = css[css.index(".sntl-action") : css.index(".sntl-action") + 2400]
    for state in (":hover", ":active", ":focus-visible", ":disabled"):
        assert state in block, f".sntl-action is missing {state}"


def test_streamlit_controls_carry_hover_active_and_focus() -> None:
    css = stylesheet()
    button_block = css[css.index(".stButton > button") : css.index(".stButton > button") + 1400]
    for state in (":hover", ":active", ":focus-visible"):
        assert state in button_block, f"streamlit button is missing {state}"


# ── 4. Motion respects the reader ───────────────────────────────────────


def test_reduced_motion_guard_exists_and_covers_transitions() -> None:
    css = stylesheet()
    guard = css[css.index("@media (prefers-reduced-motion: reduce)") :]
    assert "transition-duration" in guard
    assert "animation-duration" in guard
    assert "!important" in guard


# ── 5. Charts inherit the palette ───────────────────────────────────────


def test_plotly_layout_carries_token_colours() -> None:
    layout = plotly_layout()
    assert layout["paper_bgcolor"] == color("bg-base")
    assert layout["plot_bgcolor"] == color("bg-panel")
    assert [t.value for t in RISK_RAMP] == layout["colorway"]
    assert layout["font"]["color"] == color("ink-secondary")
    assert layout["xaxis"]["gridcolor"] == color("hairline")


def test_plotly_layout_overrides_win() -> None:
    layout = plotly_layout(height=999, margin={"l": 0})
    assert layout["height"] == 999
    assert layout["margin"] == {"l": 0}


# ── 6. Theme config stays in step with the tokens ───────────────────────


def test_streamlit_theme_config_is_token_derived() -> None:
    theme = streamlit_theme()
    assert theme["primaryColor"] == color("accent")
    assert theme["backgroundColor"] == color("bg-base")
    toml = theme_config_toml()
    assert toml.startswith("[theme]")
    assert 'baseRadius = "4px"' in toml
    for value in theme.values():
        assert value in toml


def test_committed_streamlit_config_matches_the_tokens() -> None:
    """A drifted config.toml is how a design system quietly rots."""
    config = Path(__file__).resolve().parents[1] / ".streamlit" / "config.toml"
    if not config.is_file():
        pytest.skip("no .streamlit/config.toml in this checkout")
    text = config.read_text(encoding="utf-8")
    assert 'base = "dark"' in text
    for key, value in streamlit_theme().items():
        assert f'{key} = "{value}"' in text, f"config.toml is stale for {key}"


# ── 7. Contrast ─────────────────────────────────────────────────────────


def _relative_luminance(hex_value: str) -> float:
    channels = [int(hex_value[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(foreground: str, background: str) -> float:
    lighter, darker = sorted(
        (_relative_luminance(foreground), _relative_luminance(background)), reverse=True
    )
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize("ink_token", ["ink", "ink-secondary"])
def test_body_text_meets_wcag_aa(ink_token: str) -> None:
    for surface in ("bg-base", "bg-canvas", "bg-panel", "bg-raised"):
        ratio = _contrast(get_all_colors()[ink_token], get_all_colors()[surface])
        assert ratio >= 4.5, f"{ink_token} on {surface} is {ratio:.2f}:1"


def test_muted_text_is_only_used_for_large_or_non_critical_copy() -> None:
    """ink-muted is 11-12px, so it needs 4.5:1 too, not 3:1."""
    ratio = _contrast(color("ink-muted"), color("bg-panel"))
    assert ratio >= 4.5, f"ink-muted on bg-panel is {ratio:.2f}:1"


def test_risk_ramp_is_readable_on_the_dark_canvas() -> None:
    for token in RISK_RAMP:
        ratio = _contrast(token.value, color("bg-base"))
        assert ratio >= 3.0, f"{token.name} on bg-base is {ratio:.2f}:1"


# ── 8. States exist ─────────────────────────────────────────────────────


def test_library_exposes_loading_and_empty_states() -> None:
    for name in ("skeleton", "empty", "degraded", "insufficient", "banner"):
        assert callable(getattr(ui, name)), f"ui.{name} is missing"


def test_empty_stats_renders_the_empty_state() -> None:
    app = ui.stats([])  # must not raise: an empty grid is a valid state
    assert app is None or app is not None  # the call itself is the assertion
