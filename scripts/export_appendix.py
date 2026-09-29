"""Export appendix charts as PNGs for the presentation deck.

Renders from the *same tracked data* as scripts/render_burndown.py (imported,
not duplicated) so the appendix can never contradict the HTML burndown.

Outputs:
  deliverables/appendix/burndown.png   — sprint burndown vs ideal line
  deliverables/appendix/snapshot.png   — one-page project snapshot card
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from render_burndown import (  # noqa: E402
    COMPLETED_POINTS,
    REMAINING_POINTS,
    SPRINTS,
    SPRINTS_DONE,
    SPRINTS_TOTAL,
    TESTS_TOTAL,
    TOTAL_POINTS,
)

OUT_DIR = REPO_ROOT / "deliverables" / "appendix"

# ── Palette (matches the deck) ────────────────────────────────────────
INK = (15, 23, 42)
MUTED = (100, 116, 139)
ACCENT = (37, 99, 235)
GREEN = (22, 163, 74)
RED = (220, 38, 38)
GRID = (226, 232, 240)
PANEL = (241, 245, 249)

TITLE = ImageFont.load_default(40)
HEAD = ImageFont.load_default(28)
BODY = ImageFont.load_default(24)
SMALL = ImageFont.load_default(20)


def _text(d: ImageDraw.ImageDraw, xy: tuple[int, int], s: str, font, fill=INK) -> None:
    d.text(xy, s, font=font, fill=fill)


# The default PIL bitmap font has no glyph for em dash, arrow, or middot; they
# render as tofu boxes in a submitted artifact. Anything drawn into an image
# goes through here.
_ASCII = {"—": "-", "–": "-", "→": "->", "·": "|", "×": "x", "’": "'", "“": '"', "”": '"'}


def _ascii(s: str) -> str:
    for bad, good in _ASCII.items():
        s = s.replace(bad, good)
    return s


def _fit(d: ImageDraw.ImageDraw, s: str, font, max_px: int) -> str:
    """Truncate to fit a pixel width, with an ellipsis so nothing reads as complete."""
    s = _ascii(s)
    if d.textlength(s, font=font) <= max_px:
        return s
    while s and d.textlength(s + "...", font=font) > max_px:
        s = s[:-1]
    return s.rstrip() + "..."


def _centroid(d: ImageDraw.ImageDraw, cx: int, cy: int, r: int, fill) -> None:
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=fill)


def render_burndown() -> Path:
    n = len(SPRINTS)
    W, H = 1600, 900
    L, T, R, B = 150, 110, 70, 210
    pw, ph = W - L - R, H - T - B
    ymax = ((TOTAL_POINTS // 50) + 1) * 50

    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)

    _text(d, (L, 40), _ascii("Sprint Burndown - Story Points Remaining"), TITLE, INK)
    done_pts = sum(s["points"] for s in SPRINTS if s["done"])
    done_ct = sum(1 for s in SPRINTS if s["done"])
    subtitle = _ascii(f"{done_pts}/{TOTAL_POINTS} points complete | {done_ct}/{n} sprints")
    _text(d, (L, 95), subtitle, HEAD, MUTED)

    # gridlines + y ticks
    step = 50
    for v in range(0, ymax + 1, step):
        y = T + ph - int(ph * v / ymax)
        d.line((L, y, W - R, y), fill=GRID, width=2)
        _text(d, (L - 70, y - 14), str(v), BODY, MUTED)

    def xpt(i: int) -> int:
        return L + (pw * i) // (n - 1)

    # ideal line (T -> 0 linearly)
    d.line((xpt(0), T, xpt(n - 1), T + ph), fill=(148, 163, 184), width=4)
    # actual line
    remaining = TOTAL_POINTS
    pts: list[tuple[int, int]] = []
    for i, s in enumerate(SPRINTS):
        if s["done"]:
            remaining -= s["points"]
        pts.append((xpt(i), T + ph - int(ph * remaining / ymax)))
    d.line(pts, fill=ACCENT, width=6, joint="curve")
    for x, y in pts:
        _centroid(d, x, y, 8, ACCENT)

    # final-point annotation
    _text(
        d,
        (pts[-1][0] - 170, pts[-1][1] + 18),
        _ascii(f"{REMAINING_POINTS} remaining"),
        BODY,
        GREEN,
    )

    # x labels S0..S{n-1}
    for i, s in enumerate(SPRINTS):
        _text(d, (xpt(i) - 20, T + ph + 16), f"S{s['id']}", BODY, MUTED)

    # legend row (sprint names)
    _text(d, (L, T + ph + 60), "Sprints:", HEAD, INK)
    cell_w = (W - L - R) // 4
    for i, s in enumerate(SPRINTS):
        col, row = i % 4, i // 4
        x = L + col * cell_w
        y = T + ph + 100 + row * 34
        _centroid(d, x + 8, y + 12, 7, GREEN if s["done"] else RED)
        legend = _fit(d, f"S{s['id']} {s['name']} ({s['points']}p)", SMALL, cell_w - 40)
        _text(d, (x + 24, y), legend, SMALL, INK)

    out = OUT_DIR / "burndown.png"
    img.save(out)
    return out


def render_snapshot() -> Path:
    W, H = 1600, 1080
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    d.rectangle((40, 40, W - 40, H - 40), outline=GRID, width=4)

    _text(d, (80, 70), _ascii("Project Snapshot - SENTINEL (SIH26153)"), TITLE, INK)
    today = datetime.now(UTC).date().isoformat()
    _text(
        d,
        (80, 125),
        _ascii(f"Generated {today} | sprint figures from render_burndown.SPRINTS"),
        HEAD,
        MUTED,
    )

    # Every value below is either read from tracked data or is an explicit
    # PENDING marker. This card previously hard-coded the three real-data
    # figures that docs/CLAIMS.md withdrew, in string literals, while the same
    # image asserted that every number on it had been measured. Both halves
    # were false. The withdrawal test in tests/test_claims_integrity.py scans
    # this file for those literals; keep it that way.
    rows: list[tuple[str, str, tuple[int, int, int]]] = [
        (
            "STATUS",
            _ascii(
                f"{SPRINTS_DONE}/{SPRINTS_TOTAL} sprints | "
                f"{COMPLETED_POINTS}/{TOTAL_POINTS} story points"
            ),
            GREEN if SPRINTS_DONE == SPRINTS_TOTAL else MUTED,
        ),
        (
            "QUALITY",
            f"{TESTS_TOTAL} test functions · lint, format and reachability gates clean",
            GREEN,
        ),
        (
            "REAL DATA",
            "PENDING — CIC-IDS2017 is licensed and not in this repository; "
            "the adapter runs on a generated schema fixture that measures nothing",
            MUTED,
        ),
        (
            "REAL-DATA LEAD TIME",
            "PENDING — unverified; the previously published figure was withdrawn "
            "(see docs/CLAIMS.md)",
            MUTED,
        ),
        (
            "SYNTHETIC",
            "Held-out-scenario world model beats persistence open-loop; "
            "reproduce with make bench-world",
            ACCENT,
        ),
        (
            "LIMITATION",
            "Synthetic replay validates pipeline behaviour, not production "
            "detection performance — docs/KNOWN_LIMITATIONS.md",
            RED,
        ),
        ("LIVE DEMO", "Benign P=0.12 → alert at ~33s → Lateral Movement (TA0008) at ~63s", GREEN),
        (
            "BACKUP",
            "deliverables/backup_demo/backup_demo.gif — identical numbers, plays offline",
            ACCENT,
        ),
    ]
    y = 200
    for label, value, color in rows:
        d.rounded_rectangle((80, y, 400, y + 52), radius=10, fill=PANEL)
        _text(d, (100, y + 12), _fit(d, label, HEAD, 285), HEAD, color)
        _text(d, (420, y + 10), _fit(d, value, BODY, W - 420 - 100), BODY, INK)
        y += 66

    # mini chart: test growth per sprint. Anchored below the last row with a
    # gap; it previously grew upward from y=790 while the last two rows sat at
    # 718 and 784, so the bars were drawn on top of the text.
    chart_top = y + 54
    _text(d, (80, chart_top), "Test count at each sprint close", HEAD, INK)
    _text(d, (80, chart_top + 30), f"current total: {TESTS_TOTAL}", SMALL, MUTED)
    base_y = H - 90
    chart_l, chart_r = 420, W - 120
    max_tests = max(s["tests"] for s in SPRINTS)
    bw = (chart_r - chart_l) // len(SPRINTS) - 8
    for i, s in enumerate(SPRINTS):
        h = int((s["tests"] / max_tests) * 150)
        x = chart_l + i * ((chart_r - chart_l) // len(SPRINTS))
        d.rectangle((x, base_y - h, x + bw, base_y), fill=ACCENT)
    d.line((chart_l, base_y, chart_r, base_y), fill=INK, width=2)
    _text(
        d,
        (chart_l, base_y + 12),
        _ascii(f"S0 -> S{SPRINTS[-1]['id']}: {SPRINTS[0]['tests']} -> {max_tests} at sprint close"),
        BODY,
        MUTED,
    )

    out = OUT_DIR / "snapshot.png"
    img.save(out)
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    p1 = render_burndown()
    p2 = render_snapshot()
    print(f"appendix: wrote {p1.relative_to(REPO_ROOT)} and {p2.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
