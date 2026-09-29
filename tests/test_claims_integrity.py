# SPDX-License-Identifier: Apache-2.0
"""A document may not cite an artifact this repository does not contain.

This project had a results table citing
`reports/generated/real-benchmark/REAL_BENCHMARK.md`. That file did not exist,
no CIC-IDS2017 CSV was present, and the numbers were therefore unbacked. The
rule the project already had - a number goes in a document only if a script
printed it - was not enforced anywhere, so it did not catch it.

These tests are that enforcement.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Markdown that legitimately talks about real data without claiming a run.
# research/repos is third-party reference material: it is gitignored, so its
# contents are not ours, and globbing it would let another project's README
# decide whether this repository's gate passes. Skip it.
IGNORED_DIRS = {".venv", "node_modules", ".git", "__pycache__", "planning"}
FOREIGN = ("research", "repos")
MARKDOWN = sorted(
    path
    for path in ROOT.rglob("*.md")
    if not any(part in IGNORED_DIRS for part in path.parts)
    and path.relative_to(ROOT).parts[:2] != FOREIGN
)

# Reports live under reports/generated and are deliberately not committed;
# a document may name one as a thing to generate, just not as a source it read.
GENERATED_REPORT = re.compile(r"reports/generated/[\w./-]+")
PRODUCES = re.compile(r"(uv run|make |scripts/\w+\.py|\bpython -m|\./[\w./-]+\.(sh|py))", re.I)


def test_there_are_documents_to_check() -> None:
    assert len(MARKDOWN) > 10, "the glob found almost nothing; the test is not running"


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_any_generated_report_named_also_has_a_command_that_produces_it(path: Path) -> None:
    """Naming an uncommitted report is fine; naming it with nothing to run is not.

    Reports under `reports/generated/` are deliberately not committed, so a
    document may reference one. What it must also do is say how to produce it,
    or the reference is decoration.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in GENERATED_REPORT.finditer(text):
        directory = match.group(0).rstrip(".,)`\"'").rsplit("/", 1)[0]
        if not directory:
            continue
        assert directory in text, f"{path.name} names {directory} only in a broken form"
        assert PRODUCES.search(text), (
            f"{path.name} names {directory} but contains no command that produces it; "
            "a reader cannot regenerate the number"
        )


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_document_cites_real_benchmark_md_as_a_source(path: Path) -> None:
    """The report that was cited and never existed.

    `REAL_BENCHMARK.md` was the file the real-data results table claimed to come
    from. It does not exist and, without the licensed CSVs, cannot. No document
    may point a reader at it as a source.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    assert "REAL_BENCHMARK.md" not in text, (
        f"{path.name} cites REAL_BENCHMARK.md, which does not exist in this repository"
    )


def test_the_withdrawn_real_data_section_says_so() -> None:
    results = (ROOT / "docs" / "RESULTS.md").read_text(encoding="utf-8")
    assert "NOT CURRENTLY REPRODUCIBLE" in results
    # The old table must be gone, not merely caveated.
    assert "23 of 34" not in results
    assert "**0.5**" not in results or "PENDING" in results


def test_the_abstract_does_not_claim_a_real_data_run() -> None:
    abstract = (ROOT / "deliverables" / "ABSTRACT.md").read_text(encoding="utf-8")
    assert "not measured" in abstract.lower() or "NOT measured" in abstract
    assert "23 of 34" not in abstract


def test_the_claims_file_exists_and_names_the_open_items() -> None:
    claims = ROOT / "docs" / "CLAIMS.md"
    assert claims.is_file(), "docs/CLAIMS.md is the mechanism; it must exist"
    text = claims.read_text(encoding="utf-8")
    assert "Not currently backed by an artifact" in text
    assert "CIC-IDS2017" in text
    assert "Explicitly not claimed" in text


# ── the withdrawn claim, and the document that failed to withdraw it ───────
#
# docs/RESULTS.md had its real-data table replaced with PENDING and
# ABSTRACT.md had its ~900k figure retracted. README.md was never touched: it
# kept the full five-family table AND the headline lead-time sentence, in a
# document that also states the dataset was never run. The gate above could not
# catch it because it only ever read RESULTS.md and ABSTRACT.md by name.
#
# These tests are the fix: the rule is now expressed as a fact about the whole
# gated corpus, not about two files somebody remembered.

#: Lead times that were published from the withdrawn real-data table. The
#: narrative claim is "75-second predictive lead time"; the table encoded it as
#: a half-window crossing. Both are the same withdrawn measurement.
WITHDRAWN_LEAD_TIME = re.compile(
    r"75[-\s]?(?:second|s)\b"  # 75-second / 75 second
    r"|\b75s\b"
    r"|0\.5\s*win\b",  # the table's "0.5 win (75 s)" cell
    re.I,
)

#: Documents a judge reads before anything else. These are named explicitly so
#: that adding the rule cannot quietly exclude the file that motivated it.
JUDGE_FACING = (
    "README.md",
    "docs/RESULTS.md",
    "docs/CLAIMS.md",
    "deliverables/ABSTRACT.md",
)


@pytest.mark.parametrize("relative", JUDGE_FACING, ids=JUDGE_FACING)
def test_no_judge_facing_document_republishes_the_withdrawn_lead_time(relative: str) -> None:
    """The withdrawn real-data lead time must not reappear in a headline doc.

    A withdrawn measurement that survives in one document is worse than one
    that was never published: it reads as current while contradicting the
    document that retracted it.
    """
    path = ROOT / relative
    assert path.is_file(), f"{relative} is judge-facing and must exist"
    text = path.read_text(encoding="utf-8")
    match = WITHDRAWN_LEAD_TIME.search(text)
    assert match is None, (
        f"{relative}:{text[: match.start()].count(chr(10)) + 1} republishes the withdrawn "
        f"real-data lead time ({match.group(0)!r}). The CIC-IDS2017 table was withdrawn "
        "because reports/generated/real-benchmark/ does not exist in this repository. "
        "Mark it PENDING, or restore it with a committed report."
    )


@pytest.mark.parametrize("relative", JUDGE_FACING, ids=JUDGE_FACING)
def test_judge_facing_documents_do_not_assert_the_dataset_was_benchmarked(relative: str) -> None:
    """A real-data results table may not be presented as a completed measurement.

    Guards the shape of the specific regression: a per-family table with flow
    counts and a lead-time column is a claim that the run happened, whatever
    the surrounding prose says.
    """
    text = (ROOT / relative).read_text(encoding="utf-8")
    for family in ("Infiltration", "DDoS", "Botnet", "PortScan"):
        if family not in text:
            continue
        # Any mention of a real attack family must sit next to a withdrawal.
        assert re.search(r"PENDING|withdrawn|unverified|NOT CURRENTLY", text, re.I), (
            f"{relative} names the real-data attack family {family!r} with no withdrawal "
            "marker anywhere in the document"
        )


def test_readme_manifest_of_measured_numbers_points_at_a_command() -> None:
    """README states where its numbers come from; that place must be buildable.

    It previously promised that "all numbers come from reports/generated/",
    which is gitignored and absent, making the repository's central
    reproducibility claim unfalsifiable for anyone who clones it.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert PRODUCES.search(readme), (
        "README states where its measured numbers come from but contains no command "
        "that produces them"
    )
    # The bundle is committed, so it may be cited as a source directly.
    assert "models/release" in readme, (
        "README must cite the committed release bundle as the source of its numbers"
    )


def test_the_known_limitations_file_records_the_unflattering_results() -> None:
    text = (ROOT / "docs" / "KNOWN_LIMITATIONS.md").read_text(encoding="utf-8")
    assert "Measured, not assumed" in text
    # If these are deleted the measurements become unfalsifiable again.
    assert "lateral-movement" in text
    assert "not a working simulator" in text or "barely a simulator" in text


# ── presentation generators must not re-type a withdrawn number ───────────
#
# deliverables/appendix/snapshot.png is built by scripts/export_appendix.py.
# That file hard-coded the withdrawn real-data claims (~900k flows, 23/34
# windows, 0.12-0.18 false-early) as string literals while the same image
# printed "all numbers measured, none hand-typed". Nothing gated it, because
# the image is a PNG and the text lived only in a script.

#: Figures withdrawn in docs/CLAIMS.md that must not reappear in a generator.
WITHDRAWN_FIGURES = (
    r"~?\d+\s?k\s+real flows",
    r"900,?000",
    r"23\s*[-–]\s*25\s*/\s*34",
    r"0\.12\s*[-–]\s*0\.18",
    r"none hand-typed",
    r"15 tests passing",
    r"baseline model is next",
)

GENERATORS = (
    "scripts/export_appendix.py",
    "scripts/render_burndown.py",
    "scripts/render_snapshot.py",
    "scripts/build_deck.py",
)


@pytest.mark.parametrize("relative", GENERATORS, ids=GENERATORS)
def test_no_generator_hard_codes_a_withdrawn_figure(relative: str) -> None:
    """A withdrawn number must not be typed into a script that draws it.

    These generators produce the submitted artifacts. A literal in one of them
    bypasses every markdown gate, because the claim never appears in a `.md`.
    """
    path = ROOT / relative
    if not path.is_file():
        pytest.skip(f"{relative} is not present")
    text = path.read_text(encoding="utf-8")
    for pattern in WITHDRAWN_FIGURES:
        match = re.search(pattern, text, re.I)
        assert match is None, (
            f"{relative} hard-codes {match.group(0)!r}, a figure withdrawn in "
            "docs/CLAIMS.md. Read it from tracked data or print PENDING."
        )


def test_the_real_data_sprint_is_not_marked_complete() -> None:
    """The real-data benchmark sprint may not be 'done' while its claim is open.

    docs/CLAIMS.md tracks the CIC-IDS2017 forecast table as unbacked. The
    burndown data marked the Real-Data Benchmark sprint complete, so the
    submitted chart asserted 100% delivery of a run that never happened.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import render_burndown
    finally:
        sys.path.pop(0)
    sprint = next(s for s in render_burndown.SPRINTS if "Real-Data" in s["name"])
    assert sprint["done"] is False, (
        "Real-Data Benchmark is marked done, but the licensed CSVs are absent and "
        "the run has never been executed. See docs/CLAIMS.md."
    )


def test_the_snapshot_test_count_is_measured_not_remembered() -> None:
    """The presentation test count must come from the tests on disk.

    It was the literal 111 while the suite held several times that, and the
    abstract quoted the same figure.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import render_burndown
    finally:
        sys.path.pop(0)
    on_disk = sum(
        len(re.findall(r"^\s*def test_\w+", p.read_text(encoding="utf-8"), re.M))
        for p in sorted((ROOT / "tests").glob("test_*.py"))
    )
    assert render_burndown.TESTS_TOTAL == on_disk, (
        f"TESTS_TOTAL={render_burndown.TESTS_TOTAL} but {on_disk} test functions "
        "exist on disk; the figure is derived, so these must agree"
    )


# ── the audit's numeric match is tolerance-based, on purpose ──────────────


def _claims_audit():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_claims", ROOT / "scripts" / "check_claims.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_re_measured_figure_is_matched_within_tolerance() -> None:
    """A figure may drift when its inputs are versioned; that is not a failure.

    The claims job measured +0.190 for a figure CLAIMS.md recorded as 0.189 and
    failed the build over rounding. No edit to the document can fix that, because
    re-exporting the release bundle moves the number every run. It must match on
    proximity, and say so.
    """
    audit = _claims_audit()
    available = {round(0.1904, 4): "0.1904"}
    assert audit._within_tolerance(0.189, available) == "0.1904"


def test_the_tolerance_still_rejects_a_wrong_figure() -> None:
    """Proximity matching must not become a loophole.

    Anything outside the tolerance is not produced, exactly as before. A claim
    off by 0.05 is a different measurement, not a rounding difference.
    """
    audit = _claims_audit()
    available = {round(0.1904, 4): "0.1904"}
    assert audit._within_tolerance(0.24, available) is None
    assert audit._within_tolerance(0.05, available) is None


def test_the_tolerance_is_tight_against_the_measured_environment_spread() -> None:
    """The slack is two orders of magnitude below a 3.11/3.12 torch spread.

    A different interpreter moves the world-model skill from 0.147 to 0.190, a
    0.043 gap. If the tolerance were wide enough to absorb that, it would also
    absorb a wrong figure, so it is pinned well below it.
    """
    audit = _claims_audit()
    spread = abs(0.190 - 0.147)
    slack = max(audit.TOLERANCE_ABSOLUTE, 0.147 * audit.TOLERANCE_RELATIVE)
    assert slack < spread / 5, (
        "the matching tolerance must stay far below the interpreter-dependent spread"
    )


def test_an_exact_match_is_still_an_exact_match() -> None:
    """Tolerance widens the net; it must not change what an exact hit means."""
    audit = _claims_audit()
    assert audit._within_tolerance(0.945, {round(0.945, 3): "0.945"}) == "0.945"
