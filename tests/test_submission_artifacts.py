# SPDX-License-Identifier: Apache-2.0
"""The submitted deck must not drift back into placeholders or stale figures.

`scripts/build_deck.py` reads every number from the committed release bundle
rather than typing it, so the numbers cannot rot. What it *can* still get wrong
is structure: a placeholder reintroduced, a withdrawn figure quoted, or the
project's old name back in the visible text.

The withdrawn items below are figures this project published and then retracted.
They must not appear in a judge-facing artifact, and each is named here so the
regression is obvious in the failure message rather than only in a diff.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DECK = REPO / "deliverables" / "Trajectory_SIH26153_Idea_Deck.pptx"

#: Placeholders that must never ship. The old deck had 25 of these.
PLACEHOLDERS = ("[ADD", "TODO", "TBD", "FIXME", "XXX", "Lorem ipsum", "coming soon")

#: Figures withdrawn or invalidated. Each is named so a failure says which one.
WITHDRAWN = {
    "0.892": "baseline F1 on the trivially-separable v2 corpus",
    "0.978": "baseline PR-AUC on v2",
    "0.957": "GRU h+1 F1 on v2",
    "0.941": "GRU h+5 F1 on v2",
    "0.9833": "best single-feature ROC-AUC on v2 (the shortcut)",
    "0.9933": "full-model ROC-AUC on v2",
    "0.189": "world-model open-loop skill, invalidated by the v2 shortcut",
    "0.147": "world-model open-loop skill under a different interpreter",
    "75-second": "the withdrawn real-data lead time",
    "75 s": "the withdrawn real-data lead time",
    "~900k": "the withdrawn real-flow count",
    "23-25 / 34": "the withdrawn leave-one-attack-out window count",
    "15 tests passing": "the stale Sprint-1 status line",
    "none hand-typed": "an untrue claim the old appendix printed",
}


def _text() -> str:
    if not DECK.is_file():
        pytest.skip(f"{DECK.name} not built; run scripts/build_deck.py")
    from pptx import Presentation

    prs = Presentation(DECK)
    parts = []
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                parts.append(shape.text_frame.text)
    return "\n".join(parts)


def test_the_deck_has_exactly_six_slides() -> None:
    from pptx import Presentation

    if not DECK.is_file():
        pytest.skip("deck not built")
    assert len(Presentation(DECK).slides) == 6, (
        "the submitted deck is six slides; the old one was seven"
    )


@pytest.mark.parametrize("token", PLACEHOLDERS)
def test_no_placeholder_survives_in_the_deck(token: str) -> None:
    text = _text()
    assert token.lower() not in text.lower(), (
        f"the deck contains a {token!r} placeholder. The old deck shipped 25 of them, "
        "including the headline metric. Fill it from evidence or say PENDING."
    )


@pytest.mark.parametrize("figure,why", sorted(WITHDRAWN.items()))
def test_no_withdrawn_figure_appears_in_the_deck(figure: str, why: str) -> None:
    text = _text()
    assert figure.lower() not in text.lower(), (
        f"the deck quotes {figure!r} - {why}. It was retracted in docs/CLAIMS.md and "
        "has no artifact behind it."
    )


def test_the_deck_does_not_sell_the_project_under_its_old_name() -> None:
    text = _text()
    # "Trajectory-aware" and "current trajectory" are ordinary English usage.
    # What must not survive is the old *product* name: a bare "Trajectory" used
    # as a title, a header, or "Trajectory <verb>".
    import re

    for line in text.split("\n"):
        stripped = line.strip()
        if re.fullmatch(r"trajectory(\s|\||$)", stripped, re.I):
            pytest.fail(f"the deck titles something 'Trajectory': {stripped!r}")
        if re.match(r"^trajectory\b(?!-aware)", stripped, re.I):
            pytest.fail(f"the deck presents the project as Trajectory: {stripped!r}")
        if re.search(r"\bfor trajectory\b", stripped, re.I):
            pytest.fail(f"stale product name: {stripped!r}")


def test_the_deck_states_the_real_data_claim_is_pending() -> None:
    """The withdrawn table must be visibly absent, not quietly omitted."""
    text = _text().lower()
    assert "cic-ids2017" in text, (
        "the results slide must say that real-traffic numbers are pending and why"
    )
    assert "pending" in text, "the real-data caveat must be visible on the slides"


def test_the_deck_does_not_claim_a_beatable_open_loop_skill() -> None:
    """The v3 measurement is ~0. If it is ever negative the deck must say so."""
    text = _text()
    for token in ("+0.189", "0.189", "0.947", "0.945"):
        assert token not in text, f"the deck claims an invalidated open-loop skill {token}"


def test_no_stale_pdf_ships_alongside_the_pptx() -> None:
    """A PDF that cannot be regenerated would contradict the source of truth."""
    pdf = DECK.with_suffix(".pdf")
    assert not pdf.is_file(), (
        f"{pdf.name} is present but was generated from the previous seven-slide deck. "
        "Regenerate it from the current pptx or delete it; do not ship a stale copy."
    )


def test_deliverables_explain_how_each_artifact_is_built() -> None:
    readme = REPO / "deliverables" / "README.md"
    assert readme.is_file(), "deliverables/README.md must record how each artifact is built"
    text = readme.read_text(encoding="utf-8")
    for name in ("build_deck.py", "export_appendix.py"):
        assert name in text, f"deliverables/README.md must name {name} as the generator"
