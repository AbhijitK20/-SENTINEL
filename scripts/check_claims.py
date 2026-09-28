"""Audit docs/CLAIMS.md: does every number in it come from a report this run made?

    uv run python scripts/check_claims.py

CLAIMS.md quotes figures. A figure is only honest if a script in this repository
produced it, so this pulls the numbers straight out of the "Backed by a test,
numbers produced by a script" table and looks for each one in the reports under
``reports/generated/``.

It reads CLAIMS.md rather than keeping its own list, because a second copy of the
claims is a second thing to forget to update - which is how a document starts
lying.

**What this does and does not establish.** Each figure is looked for in the report
its own command writes, at the precision the claim states. That catches a figure
no script produced. It does **not** prove the figure belongs to the claim quoting
it: a claim of 0.777 matches an unrelated 0.7770031 in the same file, because
numeric matching cannot tell which JSON key a number came from. The matched value
is printed so a reader can see what it actually hit, and a figure that passes here
still has to be read. Treat a pass as "this number came out of today's run", not
as "this claim is verified".
"""

from __future__ import annotations

import re
from pathlib import Path

CLAIMS = Path("docs/CLAIMS.md")
REPORTS = Path("reports/generated/benchmark")

# Where each make target's output lands. Keyed on the Command column in CLAIMS.md
# rather than on the claim text, so this table is a map of where output goes -
# which is stable - and not a second copy of the claims, which would not be.
TARGET_REPORTS: dict[str, tuple[str, ...]] = {
    "make bench-backtest": ("backtest/backtest.json",),
    "make bench-detectors": ("detectors/detector_benchmark.json",),
    "make bench-world": ("world_model/world_model_benchmark.json", "world_model/world_model.json"),
    "make bench-telemetry": ("telemetry/telemetry_budget.json",),
    "make bench-evasion": ("evasion/evasion.json",),
    "make bench-labels": ("label-efficiency/label_efficiency.json",),
    "make bench-drift": ("drift/drift.json",),
    "make bench-calibration": ("calibration/calibration.json",),
    "make bench-perf": ("perf-profile/perf_profile.json",),
    "make bench": ("benchmark.json",),
}

# Scoping each claim to its own report is the whole point. A version of this that
# searched every report matched a fabricated 0.777 against an unrelated 0.7770031
# in the world-model file, which is the same class of mistake the check exists to
# catch.
NUMBER = re.compile(r"(?<![\w.])\d+\.\d+(?![\w.])")


def _measured_rows() -> list[tuple[str, str, str]]:
    """Return (claim, command, number) for every figure in the measured table."""
    text = CLAIMS.read_text(encoding="utf-8")
    for section in text.split("## "):
        if not section.startswith("Backed by a test, numbers produced by a script"):
            continue
        rows: list[tuple[str, str, str]] = []
        for line in section.splitlines():
            if not line.startswith("|") or line.startswith("|---") or line.startswith("| Claim"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 3:
                continue
            claim, command, measured = cells[0], cells[1].strip("`"), cells[2]
            for number in NUMBER.findall(measured):
                rows.append((claim, command, number))
        return rows
    return []


def _numbers_in(reports: tuple[str, ...]) -> dict[float, str] | None:
    """Decimals from the named reports, mapped to the token they came from."""
    found: dict[float, str] = {}
    seen = False
    for relative in reports:
        for path in (REPORTS / relative, (REPORTS / relative).with_suffix(".md")):
            if not path.exists():
                continue
            seen = True
            try:
                body = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for token in NUMBER.findall(body):
                value = float(token)
                for places in (2, 3, 4):
                    found.setdefault(round(value, places), token)
    return found if seen else None


def main() -> None:
    rows = _measured_rows()
    if not rows:
        print("No measured-claims table found in docs/CLAIMS.md - nothing to audit.")
        return

    untraced: list[tuple[str, str, str]] = []
    unverifiable: list[tuple[str, str, str]] = []
    for claim, command, number in rows:
        reports = TARGET_REPORTS.get(command)
        if reports is None:
            unverifiable.append((claim, command, f"no report mapped for `{command}`"))
            continue
        available = _numbers_in(reports)
        if available is None:
            unverifiable.append((claim, command, f"{reports[0]} not generated in this run"))
        elif round(float(number), 3) not in available:
            untraced.append((claim, command, number))

    for claim, command, number in untraced:
        print(f"NOT PRODUCED  {number:<8} {claim}  ({command})")
    for claim, _, why in unverifiable:
        print(f"UNVERIFIED    {claim}  ({why})")
    total = len(rows)
    print()
    print(
        f"{total - len(untraced) - len(unverifiable)}/{total} figures appear in the report "
        "their command writes"
    )
    print(
        "A pass means the number came out of today's run, not that the claim is verified: "
        "numeric matching\ncannot tell which field a number came from, so the row still "
        "has to be read."
    )
    if untraced:
        print(
            "Each NOT PRODUCED figure was not printed by the script its row names. "
            "Re-measure or remove it."
        )
    # Non-zero exit, or the CI job this runs in is decoration. "I did not check it"
    # and "it is wrong" must not both look like success.
    raise SystemExit(1 if (untraced or not rows or not _numbers_in(("benchmark.json",))) else 0)


if __name__ == "__main__":
    main()
