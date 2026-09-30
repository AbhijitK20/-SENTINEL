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


# ── The feature-name contract between the attack script and the detectors ──

#: Feature names the detection path actually reads. state_builder accumulates
#: edge bytes only from ``bytes``/``payload_size``, and the credential detector
#: derives its per-minute rate from ``failed_auth``; the recon detector from
#: ``rst_count``. Emitting anything else leaves every aggregate at zero.
DETECTOR_READS = ("bytes", "failed_auth", "syn_count", "rst_count")


def test_every_event_carries_the_features_the_detectors_read() -> None:
    """No phase may emit an event the detection path cannot read.

    This is the regression: the suite emitted bytes_sent/bytes_received/
    failed_auth_per_min, so 127 real events produced ~1e-111 peak probability
    and 0.222 coverage while every HTTP request had genuinely succeeded.
    """
    events = full_attack._detector_features({"bytes_sent": 44.0, "bytes_received": 0.0})
    assert "bytes" in events, "edge byte volume comes only from bytes/payload_size"


def test_originals_are_kept_so_the_dashboard_can_still_report_them() -> None:
    """The translation adds names; it must not discard what produced them."""
    out = full_attack._detector_features(
        {"bytes_sent": 100.0, "bytes_received": 20.0, "http_status": 200.0}
    )
    assert out["bytes_sent"] == 100.0
    assert out["bytes_received"] == 20.0
    assert out["http_status"] == 200.0
    assert out["bytes"] == 120.0


def test_failed_auth_becomes_a_per_flow_indicator_not_a_rate() -> None:
    """The detector multiplies by flow count itself; a rate would overshoot."""
    out = full_attack._detector_features({"failed_auth_per_min": 1.0})
    assert out["failed_auth"] == 1.0


def test_absent_telemetry_is_not_invented() -> None:
    """A feature the HTTP phases cannot support must stay absent.

    Malware process executions, DNS tunnel markers and query names have no
    honest source here. Fabricating them would be the failure mode the
    project's own rules exist to prevent.
    """
    out = full_attack._detector_features({"http_status": 404.0})
    for absent in ("malware_process_executions", "dns_tunnel_marker", "domain_length"):
        assert absent not in out


def test_dry_run_phases_all_produce_detector_readable_events() -> None:
    """Every phase, through the real helper, emits at least one readable name."""
    samples = {
        "ddos": {"bytes_sent": 200.0, "syn_ratio": 0.8},
        "recon": {"dst_port": 22.0, "bytes_sent": 44.0, "rst_ratio": 1.0},
        "brute_force": {"failed_auth_per_min": 1.0, "bytes_sent": 60.0},
    }
    for name, features in samples.items():
        out = full_attack._detector_features(features)
        assert any(key in out for key in DETECTOR_READS), name


def test_coverage_is_not_computed_from_a_truncated_finding_buffer() -> None:
    """A demo suite must not evict its own evidence.

    Findings are one per detector per window, so the 9-phase suite produced
    9 x 99 = 891 against a 600-entry buffer: the reconnaissance findings from
    the first 33 windows were gone, and /v1/attack-coverage reported T1046 at
    0.17 for a phase that measures 1.0 on its own. The bound is now above a
    full suite, and the response reports evictions instead of hiding them.
    """
    from sentinel.live import MAX_RETAINED_FINDINGS

    assert MAX_RETAINED_FINDINGS >= 9 * 99, (
        "the retained-findings bound must survive a full 9-phase demo suite"
    )


def test_lateral_phase_pivots_across_repeated_internal_hosts(monkeypatch) -> None:
    """Lateral must revisit internal edges, not emit one fresh edge per call.

    ``detect_lateral`` scores bytes on internal edges already present in the
    previous ``LATERAL_LOOKBACK`` windows. A single-actor phase pointed at one
    host made every window look like a brand-new edge, so the known-edge byte
    count stayed at zero and the detector could not fire at any volume.
    """
    from datetime import UTC, datetime

    monkeypatch.setattr(full_attack, "_get", lambda target, path: (200, b"x" * 8192))
    events = full_attack.phase_lateral("http://target", datetime.now(UTC))

    edges = {(e.source_entity, e.destination_entity) for e in events}
    sources = {e.source_entity for e in events}
    destinations = {e.destination_entity for e in events}

    # more than one internal source host, so a pivot is actually represented
    assert len(sources) > 1, sources
    assert len(edges) > 1, edges
    # a single destination the pivots converge on
    assert len(destinations) == 1, destinations
    # each source is visited more than once, so edges become "known" in history
    for src in sources:
        assert sum(1 for e in events if e.source_entity == src) > 1, src
    # and the volume has to clear the detector's byte-rate band
    assert max(e.features.get("bytes", 0.0) for e in events) >= full_attack.PIVOT_BYTES


def test_lateral_phase_is_detected_by_the_lateral_rule(monkeypatch) -> None:
    """End-to-end: the emitted phase must actually raise the lateral detector."""
    from datetime import UTC, datetime

    from sentinel.detectors import DetectorContext, DetectorSet, detect_lateral
    from sentinel.state_builder import build_network_states

    monkeypatch.setattr(full_attack, "_get", lambda target, path: (200, b"x" * 8192))
    events = full_attack.phase_lateral("http://target", datetime.now(UTC))
    states = build_network_states(events, window_seconds=4.0, stride_seconds=4.0)

    history: list = []
    alerts = 0
    for state in states:
        finding = detect_lateral(
            DetectorContext(state=state, history=history, deployment_baseline=None),
            DetectorSet(),
        )
        if finding.is_alert:
            alerts += 1
        history.append(state)

    assert alerts, "lateral movement was not detected by its own detector"


def test_lateral_phase_spans_enough_windows_for_detector_history(monkeypatch) -> None:
    """Lateral must occupy several windows, not one burst.

    `detect_lateral` scores an edge only after it has been seen in a previous
    window, so a phase whose events all land inside a single window leaves
    history at depth 1 and can never fire however much volume it carries. The
    phase therefore has to fill several whole windows.
    """
    from datetime import UTC, datetime

    from sentinel.state_builder import build_network_states

    monkeypatch.setattr(full_attack, "_get", lambda target, path: (200, b"x" * 8192))
    events = full_attack.phase_lateral("http://target", datetime.now(UTC))
    # the same 60 s / 30 s geometry the API's push engine runs
    states = build_network_states(events, window_seconds=60.0, stride_seconds=30.0)

    assert len(states) >= 4, f"only {len(states)} window(s); history cannot reach MIN_HISTORY"


def test_lateral_phase_carries_enough_bytes_to_clear_the_band(monkeypatch) -> None:
    """Lateral volume has to exceed detect_lateral's 750-900 B/s band.

    The phase used to emit 64 B responses. Against a 60 s window that is five
    orders of magnitude under the floor, so the rule could not score above zero
    no matter how many windows the phase spanned.
    """
    from sentinel.detectors import KNOWN_EDGE_BYTES_PER_SEC_ALERT

    window_bytes = full_attack.PIVOT_BYTES * 3  # three pivoted hosts
    rate = window_bytes / full_attack.WINDOW_SECONDS
    assert rate >= KNOWN_EDGE_BYTES_PER_SEC_ALERT, (
        f"{rate:.0f} B/s is under the {KNOWN_EDGE_BYTES_PER_SEC_ALERT:g} B/s alert floor"
    )
