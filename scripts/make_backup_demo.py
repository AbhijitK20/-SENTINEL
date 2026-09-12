"""Backup demo: render the rehearsed live-demo timeline into shareable frames.

Generates a frame per narrated beat (dark theme, matching the dashboard) and
stitches them into an animated GIF that loops as the fallback demo if the
live infrastructure fails at the venue. Uses Pillow only — no new deps.

    uv run python scripts/make_backup_demo.py
    # outputs: deliverables/backup_demo/frame_XX_*.png + backup_demo.gif
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "deliverables" / "backup_demo"
W, H = 1280, 720

BG = (11, 13, 18)
PANEL = (17, 21, 30)
ACCENT = (109, 211, 168)
ALERT = (239, 111, 111)
TEXT = (232, 236, 244)
MUTED = (140, 148, 163)

# The rehearsed beats (measured 2026-09-13 by scripts/rehearse_demo.py —
# reports/generated/rehearsal.json is the source of truth for these numbers).
BEATS = (
    ("t=19s", "Benign background chatter", "P(infiltration) = 0.12", "Stage: Unknown", ACCENT),
    (
        "t=34s",
        "Scan burst detected",
        "P(infiltration) = 0.99",
        "ALERT — Initial Access (TA0001)",
        ALERT,
    ),
    (
        "t=49s",
        "Failed logins observed",
        "P(infiltration) = 1.00",
        "Stage: Initial Access (TA0001)",
        ALERT,
    ),
    (
        "t=64s",
        "Bulk internal transfer",
        "P(infiltration) = 1.00",
        "ESCALATION — Lateral Movement (TA0008)",
        ALERT,
    ),
)


def _curve_frame(progress: float, last: int) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw.text((40, 28), "Trajectory — Live Detection (backup demo)", fill=TEXT)
    draw.text(
        (40, 52), "localhost demo attack · window 30s / stride 15s · threshold 0.50", fill=MUTED
    )

    # Chart panel with threshold line.
    chart = (60, 110, W - 60, H - 220)
    draw.rectangle(chart, outline=PANEL, width=2)
    threshold_y = chart[3] - int((chart[3] - chart[1]) * 0.5)
    for offset in range(chart[0], chart[2], 24):
        draw.point((offset, threshold_y), fill=MUTED)
    draw.text((chart[0] + 8, threshold_y - 22), "threshold 0.50", fill=MUTED)

    # Probability curve across beats.
    probs = (0.12, 0.99, 1.00, 1.00)
    points = []
    for index, prob in enumerate(probs):
        x = chart[0] + int((chart[2] - chart[0]) * (0.15 + 0.28 * index))
        y = chart[3] - int((chart[3] - chart[1]) * prob)
        points.append((x, y))
    if len(points) > 1:
        draw.line(points[: last + 1], fill=ACCENT, width=4)
    for index, (x, y) in enumerate(points[: last + 1]):
        color = ALERT if probs[index] >= 0.5 else ACCENT
        draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill=color)

    # Current reading panel.
    label, story, prob_text, stage_text, color = BEATS[last]
    draw.rectangle((60, H - 190, W - 60, H - 60), outline=PANEL, width=2)
    draw.text((84, H - 170), f"{label}  ·  {story}", fill=TEXT)
    draw.text((84, H - 136), prob_text, fill=color)
    draw.text((84, H - 104), stage_text, fill=color)
    draw.text(
        (84, H - 78),
        "OBSERVED window features · FORECAST probability from trained artifacts",
        fill=MUTED,
    )
    return img


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fps", type=float, default=1.0, help="frames per second in the GIF")
    parser.parse_args()  # reserved: frame pacing currently uses per-beat durations

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    frames: list[Image.Image] = []
    for index in range(len(BEATS)):
        frame = _curve_frame(0.0, index)
        path = OUT_DIR / f"frame_{index}_{BEATS[index][0].replace('=', '').replace(' ', '')}.png"
        frame.save(path)
        frames.append(frame)
        print(f"frame: {path.name}")

    # Animated GIF: hold the alert beat slightly longer for narration.
    gif_path = OUT_DIR / "backup_demo.gif"
    durations = [2200, 2600, 2200, 3000]
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
    )
    print(f"gif: {gif_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
