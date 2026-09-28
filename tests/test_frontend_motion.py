"""The motion layer is a system; these tests hold it to that.

Motion is the easiest thing to add and the hardest to keep honest: an animation
with no purpose is a accessibility regression, an animation that fires on every
redraw makes a streaming surface unreadable, and a stylesheet that grows
keyframes without a reduced-motion guard is a trap.
"""

from __future__ import annotations

import re

import pytest

from sentinel.frontend import ui
from sentinel.frontend.theme import stylesheet

KEYFRAMES = re.compile(r"@keyframes\s+([\w-]+)\s*\{")
ANIMATION_USE = re.compile(r"animation:\s*([\w-]+)")
INFINITE = re.compile(r"infinite")


def _keyframes() -> set[str]:
    css = stylesheet().replace("{{", "{").replace("}}", "}")
    return set(KEYFRAMES.findall(css))


def test_every_animation_references_a_defined_keyframe() -> None:
    """A typo in a keyframe name silently disables the animation."""
    css = stylesheet().replace("{{", "{").replace("}}", "}")
    defined = set(KEYFRAMES.findall(css))
    assert defined, "the stylesheet defines no keyframes"
    for name in ANIMATION_USE.findall(css):
        assert name in defined, f"animation references undefined keyframe {name!r}"


def test_motion_covers_all_four_purposes() -> None:
    """Value arrived, state changed, attention needed, surface acted on."""
    defined = _keyframes()
    for required in (
        "sntl-rise",  # value arrived
        "sntl-grow-x",  # value arrived (quantities)
        "sntl-pop",  # state changed
        "sntl-pulse-ring",  # attention
        "sntl-breathe",  # attention
        "sntl-sheen",  # attention
    ):
        assert required in defined, f"missing {required}"


def test_interactive_transitions_use_motion_tokens() -> None:
    """Every hover/press/focus transition takes its duration from a token.

    This is the enforceable form of "durations come from the system": the
    interaction timings are the ones a reader perceives as latency, so they are
    the ones that must be consistent across components.
    """
    css = stylesheet().replace("{{", "{").replace("}}", "}")
    # Rules that declare a transition, split into individual declarations.
    transition_rules = re.findall(
        r"([^{}]+)\{((?:[^{}]|\{[^{}]*\})*?transition:[^;}]+;[^}]*)\}", css
    )
    assert transition_rules, "no transition rules found"

    offenders = []
    for selector, body in transition_rules:
        for declaration in re.findall(r"transition:\s*([^;]+);", body):
            for duration in re.findall(r"\b(\d+m?s)\b", declaration):
                offenders.append(f"{selector.strip()} → {duration}")
    assert not offenders, f"transition durations not taken from tokens: {offenders}"


def test_motion_token_durations_are_all_referenced() -> None:
    """The token set is not decorative: the stylesheet uses it."""
    css = stylesheet()
    for name in ("fast", "normal", "slow", "page"):
        assert f"--motion-duration-{name}" in css


def test_stagger_uses_a_css_variable_not_inline_timing() -> None:
    css = stylesheet().replace("{{", "{").replace("}}", "}")
    assert "var(--stagger" in css
    assert "animation-delay" in css


def test_infinite_loops_are_limited_to_attention_and_ambient() -> None:
    """A dashboard where everything loops is a dashboard nobody can read."""
    css = stylesheet().replace("{{", "{").replace("}}", "}")
    infinite_rules = re.findall(r"([^{}]+)\{[^}]*" + INFINITE.pattern + r"[^}]*\}", css)
    selectors = [s.strip().splitlines()[-1].strip() for s in infinite_rules]
    allowed = (
        "sntl-meter__threshold",
        "sntl-meter__band",
        "sntl-banner--degraded::after",
        "sntl-banner--error::after",
        "sntl-stage--live .sntl-stage__dot",
        "sntl-stage--severe .sntl-stage__dot",
        "sntl-live-dot",
        "sntl-spine__tick--attack .sntl-spine__bar",
        "sntl-empty__icon",
        "sntl-header__mark",
        "body::before",
        "sntl-skeleton",  # a loading shimmer is itself an attention surface
    )
    for selector in selectors:
        assert any(selector.startswith(a) or a in selector for a in allowed), (
            f"{selector!r} loops forever but is not an attention or ambient surface"
        )


def test_reduced_motion_stops_everything() -> None:
    css = stylesheet().replace("{{", "{").replace("}}", "}")
    guard = css[css.index("@media (prefers-reduced-motion: reduce)") :]
    assert "animation-duration: 0.001ms" in guard
    assert "animation-iteration-count: 1" in guard
    assert "transition-duration: 0.001ms" in guard
    # The decorative surfaces are removed outright, not just shortened.
    for selector in ("body::before", "sntl-banner::after", "sntl-spine::before"):
        assert selector in guard, f"{selector} survives reduced motion"


def test_stat_tiles_declare_tabular_figures() -> None:
    """A changing number must not reflow its neighbours while it animates."""
    css = stylesheet()
    assert "font-variant-numeric: tabular-nums" in css


def test_change_detection_is_available_to_components() -> None:
    assert hasattr(ui, "live_value")
    assert hasattr(ui, "stats")
    stat = ui.Stat(label="x", value="1", changed=True)
    assert stat.changed is True


@pytest.mark.parametrize("probability", [0.0, 0.3, 0.6, 0.95])
def test_band_names_cover_the_ramp_for_attention_levels(probability: float) -> None:
    from sentinel.frontend.tokens import risk_band

    assert risk_band(probability) in {
        "quiet",
        "elevated",
        "concerning",
        "critical",
        "severe",
    }
