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


def test_the_known_limitations_file_records_the_unflattering_results() -> None:
    text = (ROOT / "docs" / "KNOWN_LIMITATIONS.md").read_text(encoding="utf-8")
    assert "Measured, not assumed" in text
    # If these are deleted the measurements become unfalsifiable again.
    assert "lateral-movement" in text
    assert "not a working simulator" in text or "barely a simulator" in text


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
