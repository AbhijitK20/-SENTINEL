"""Rehearsal harness for the SIH live demo.

Runs the exact demo path deterministically at stage conditions:
artifact load, source start, live windows, alert, stage escalation —
measuring each beat so the presentation timing is known, not guessed.

    uv run python scripts/rehearse_demo.py --output reports/generated/rehearsal.json

It does not start a browser or the streamlit server (the streamlit smoke test
covers that); it exercises everything under the UI plus the same defaults the
Live tab uses.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from trajectory.live import JsonlSensorSource, LiveEngine  # noqa: E402
from trajectory.predict import load_artifacts  # noqa: E402

ARTIFACTS = ROOT / "reports" / "generated" / "baseline"
EVENTS = Path("/tmp/live-events.jsonl")
# The Live tab defaults (window 30s / stride 15s) — narration assumes these.
WINDOW_S = 30
STRIDE_S = 15
# The demo attack's speed setting on the Start button.
DEMO_SPEED = 2.0

PHASES = ("benign", "recon", "failed-logins", "lateral")
PHASE_SECONDS = (40.0, 30.0, 30.0, 40.0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports/generated/rehearsal.json")
    args = parser.parse_args()

    report: dict = {"generated_at": datetime.now(tz=UTC).isoformat()}

    # ── Beat 1: artifact load (the "Train / Retrain" equivalent) ──────
    t0 = time.monotonic()
    loaded = load_artifacts(ARTIFACTS)
    report["artifact_load_seconds"] = round(time.monotonic() - t0, 2)

    # ── Launch target + attack exactly like the Start button does ─────
    EVENTS.parent.mkdir(parents=True, exist_ok=True)
    EVENTS.write_text("", encoding="utf-8")
    target = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "attack_demo.py"), "target"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    attack = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "scripts" / "attack_demo.py"),
            "attack",
            "--events",
            str(EVENTS),
            "--speed",
            str(DEMO_SPEED),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    engine = LiveEngine(
        loaded,
        source=JsonlSensorSource(EVENTS, poll_seconds=0.2),
        window_seconds=WINDOW_S,
        stride_seconds=STRIDE_S,
        history=3,
    )
    engine.start()

    beats: list[dict] = []
    alert_at: float | None = None
    lateral_at: float | None = None
    started = time.monotonic()

    try:
        while time.monotonic() - started < 150:  # attack is ~70s at speed 2
            time.sleep(1.0)
            status = engine.poll()
            elapsed = time.monotonic() - started
            if not status.history:
                continue
            latest = status.history[-1]
            # New window? record a beat.
            if not beats or beats[-1]["window_start"] != latest.window_start.isoformat():
                beats.append(
                    {
                        "t": round(elapsed, 1),
                        "window_start": latest.window_start.isoformat(),
                        "events": latest.event_count,
                        "probability": round(latest.probability, 3),
                        "stage": latest.stage,
                        "mitre": latest.mitre_reference,
                    }
                )
            if latest.probability >= latest.threshold and alert_at is None:
                alert_at = elapsed
                beats[-1]["is_alert"] = True
            if latest.stage == "Lateral Movement" and lateral_at is None:
                lateral_at = elapsed
                beats[-1]["is_escalation"] = True
            if lateral_at is not None and elapsed > lateral_at + 10:
                break  # story complete; hold ~10s on the final beat, then end
            if not status.running and status.history:
                break

        report["beats"] = beats
        report["time_to_first_alert_s"] = round(alert_at, 1) if alert_at else None
        report["time_to_lateral_s"] = round(lateral_at, 1) if lateral_at else None
        # Benign = windows strictly before the first flagged alert beat
        # (index-based: beat times are rounded, timestamps are not comparable).
        first_alert_idx = next((i for i, b in enumerate(beats) if b.get("is_alert")), len(beats))
        pre_alert = beats[:first_alert_idx]
        report["max_probability_benign"] = max((b["probability"] for b in pre_alert), default=None)
        report["total_demo_seconds"] = round(time.monotonic() - started, 1)
        report["narrated_story_seconds"] = (
            round(lateral_at, 1) if lateral_at else None
        )  # time from start to the final stage beat; tail narration adds ~10s
        report["windows_emitted"] = len(beats)
        report["pass"] = bool(
            alert_at and lateral_at and (report["max_probability_benign"] or 1.0) < 0.5
        )
    finally:
        engine.stop()
        attack.terminate()
        target.terminate()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nrehearsal report: {out}")


if __name__ == "__main__":
    main()
