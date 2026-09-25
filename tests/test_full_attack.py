import importlib.util
from pathlib import Path

import pytest

from sentinel.attack_phases import MITRE, PHASES, parse_summary

SCRIPT = Path(__file__).parents[1] / "scripts" / "full_attack.py"
SPEC = importlib.util.spec_from_file_location("full_attack", SCRIPT)
assert SPEC and SPEC.loader
full_attack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(full_attack)


def test_unknown_phase_name_fails_loudly() -> None:
    """A phase name the script does not implement must not silently run nothing."""
    with pytest.raises(SystemExit) as exc:
        full_attack.main(["--phases", "enum", "--dry-run"])
    assert exc.value.code != 0


def test_registry_covers_every_documented_attack() -> None:
    """The registry is the single source of truth for attack buttons and phases."""
    assert [p["name"] for p in PHASES] == [
        "ddos",
        "recon",
        "brute_force",
        "injection",
        "lateral",
        "exfil",
        "c2",
        "insider",
        "malware",
    ]


def test_registry_entry_declares_display_and_technique() -> None:
    """Each button needs a label, description and the technique it targets."""
    for phase in PHASES:
        assert phase["label"], phase["name"]
        assert phase["description"], phase["name"]
        # A phase with no detector must say so rather than imply coverage.
        if phase["detector"] is None:
            assert phase["technique"] is None, phase["name"]
        else:
            assert phase["technique"] == MITRE[phase["detector"]], phase["name"]


def test_phases_without_a_detector_are_an_explicit_known_gap() -> None:
    """SENTINEL has no injection detector; the gap is recorded, not hidden."""
    assert [p["name"] for p in PHASES if p["detector"] is None] == ["injection"]


def test_each_phase_tags_its_events_with_its_own_name() -> None:
    """Events must be attributable to the phase that produced them."""
    base = full_attack.datetime.now(full_attack.UTC)
    events = full_attack.phase_exfil("http://127.0.0.1:1", base)
    assert events
    assert all(e.provenance.startswith("full-attack:exfiltration:") for e in events)


def test_summary_json_reports_per_phase_extracted_data(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The dashboard parses this block to show what each phase extracted."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            full_attack,
            "push",
            lambda api, key, events: {
                "events_seen": len(events),
                "windows_emitted": 0,
                "alert_status": "below-threshold",
                "peak_probability": 0.0,
                "incidents": [],
            },
        )
        mp.setattr(full_attack, "_post", lambda target, path, data=None: (401, b"nope"))
        mp.setattr(full_attack, "_get", lambda target, path: (200, b"x" * 512))
        code = full_attack.main(
            [
                "--phases",
                "brute_force",
                "exfil",
                "--api",
                "http://api.invalid",
                "--summary-json",
            ]
        )
    assert code == 0
    summary = parse_summary(capsys.readouterr().out)
    assert {row["phase"] for row in summary["phases"]} == {"brute_force", "exfil"}
    exfil = next(r for r in summary["phases"] if r["phase"] == "exfil")
    assert exfil["events"] == 6
    assert exfil["bytes_received"] > 0
    assert exfil["http_statuses"] == {200: 6}
