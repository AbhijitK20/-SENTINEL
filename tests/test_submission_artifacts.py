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

import re
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


# ── stale-figure sweep across the judge-facing corpus ───────────────────

#: Figures from the withdrawn `synthetic-recon-lateral-v2` corpus. Each one is
#: retired. A document may still *name* one when it is explaining the withdrawal
#: — the words "withdrawn", "v2" and "shortcut" are what make that legitimate —
#: so the rule is contextual rather than a bare ban.
RETIRED_FIGURES = {
    "0.892": "baseline F1 on v2",
    "0.978": "baseline PR-AUC on v2",
    "0.957": "GRU h+1 F1 on v2",
    "0.812": "lateral precision on v2",
    "0.686": "recon precision on v2",
    "0.189": "world-model open-loop skill on v2",
    "0.9833": "single-feature ROC-AUC on v2",
    "0.9933": "full-model ROC-AUC on v2",
    "0.0072": "the full-minus-single gap on v2",
    "0.9861": "single-feature ROC-AUC, the v2 report",
    "2.7 × 10⁵": "linear spectral norm, v2 fit",
    "2.5×": "transformer-vs-lstm reconstruction ratio, v2",
}

# `0.945`, `0.963` and `0.929` are deliberately absent: the first is a genuine
# v3 train-split stage macro-F1 and the others appear as legitimate v3 values, so
# a bare string ban on them would fail on correct data. The lateral and recon
# figures are pinned instead by `test_readme_states_the_current_detector_numbers`
# and by the banner test on KNOWN_LIMITATIONS.md.
#
#: Where a retired figure may legitimately appear, and what must accompany it.
WITHDRAWAL_MARKERS = (
    "withdraw",
    "v2",
    "shortcut",
    "historical",
    "artefact",
    "artifact",
    "earlier",
    "previously",
    "no longer",
    "trivial",
)

JUDGE_FACING = (
    "README.md",
    "docs/RESULTS.md",
    "docs/CLAIMS.md",
    "docs/ARCHITECTURE.md",
    "deliverables/ABSTRACT.md",
)


@pytest.mark.parametrize("relative", JUDGE_FACING, ids=JUDGE_FACING)
def test_a_retired_figure_is_only_ever_mentioned_as_withdrawn(relative: str) -> None:
    """A v2 number must not be readable as a current measurement.

    This is the failure the audit found: `docs/RESULTS.md` carried a blockquote
    explaining that the numbers were superseded and then, forty lines below, a
    table quoting exactly those numbers with no marker. A reader skimming for
    the result would take the table.
    """
    lines = (REPO / relative).read_text(encoding="utf-8").split("\n")
    for index, line in enumerate(lines):
        for figure, why in RETIRED_FIGURES.items():
            if figure not in line:
                continue
            window = " ".join(lines[max(0, index - 4) : index + 3]).lower()
            if any(marker in window for marker in WITHDRAWAL_MARKERS):
                continue
            # A table row or a bullet is a *claim*. Prose that is explaining
            # something else may legitimately mention the number.
            stripped = line.strip()
            assert not (stripped.startswith("|") or stripped.startswith("-")), (
                f"{relative}:{index + 1} presents {figure!r} ({why}) as a claim - a table "
                f"row or bullet - with no withdrawal marker within 4 lines: {stripped[:100]!r}"
            )


def test_known_limitations_flags_its_pre_2026_figures() -> None:
    """The limitations file keeps old numbers on purpose; it must say so."""
    text = (REPO / "docs" / "KNOWN_LIMITATIONS.md").read_text(encoding="utf-8")
    assert "predate 2026-09-29" in text, (
        "KNOWN_LIMITATIONS.md keeps tables measured on the withdrawn v2 corpus; it must "
        "carry a banner saying the numbers are historical"
    )
    for figure in ("0.945", "0.686", "0.189"):
        idx = text.find(figure)
        if idx == -1:
            continue
        window = text[max(0, idx - 900) : idx + 900].lower()
        assert any(m in window for m in ("historical", "v2", "withdrawn", "current")), (
            f"{figure} appears in KNOWN_LIMITATIONS.md with no historical marker nearby"
        )


def test_readme_states_the_current_detector_numbers() -> None:
    """The headline detector figures must match the last benchmark run."""
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for figure in ("0.765", "0.481", "0.591", "0.794"):
        assert figure in readme, (
            f"README should carry the current detector figure {figure}; it may be quoting "
            "a retired measurement"
        )


def test_the_abstract_quotes_the_current_test_count() -> None:
    """A remembered test count is wrong within two sprints of writing it.

    The abstract claimed "111/111 tests" while the suite held 1020. The number
    is cheap to obtain and expensive to defend, so it is derived here rather
    than trusted.
    """
    abstract = (REPO / "deliverables" / "ABSTRACT.md").read_text(encoding="utf-8")
    on_disk = sum(
        len(re.findall(r"^\s*def test_\w+", p.read_text(encoding="utf-8"), re.M))
        for p in sorted((REPO / "tests").glob("test_*.py"))
    )
    claimed = re.search(r"\*\*(\d[\d,]*) test functions across (\d+) files\*\*", abstract)
    assert claimed, (
        "the abstract must state how many test functions exist, so it can be derived "
        "rather than remembered"
    )
    files = len(list((REPO / "tests").glob("test_*.py")))
    assert int(claimed.group(1).replace(",", "")) == on_disk, (
        f"the abstract claims {claimed.group(1)} test functions; {on_disk} exist on disk. "
        "Do not hand-write this number."
    )
    assert int(claimed.group(2)) == files, (
        f"the abstract claims {claimed.group(2)} test files; {files} exist on disk"
    )
