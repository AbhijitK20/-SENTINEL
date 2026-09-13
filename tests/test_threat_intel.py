"""Tests for threat-intel feeds, detector enrichment, and deploy bootstrap."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trajectory.detectors import DetectorSet, run_all_detectors
from trajectory.schemas import NetworkState
from trajectory.threat_intel import ThreatIntelFeed, evaluate_hosts

URLHAUS_SAMPLE = (
    "# urlhaus CSV sample\n"
    "id,dateadded,url,url_status,threat,tags,urlhaus_reference\n"
    "1,2026-01-01 00:00:00 UTC,http://evil.example.com/payload.bin,online,malware_download,elf,\n"
    "2,2026-01-01 00:01:00 UTC,http://bad-host.io:8080/x,offline,malware_download,exe,\n"
)

# Real https://urlhaus.abuse.ch/downloads/csv/ payload shape (headerless, quoted,
# ZIP-wrapped csv.txt): banner comment lines, then 8 quoted columns, URL at index 2.
URLHAUS_REAL_DUMP = (
    "################################################################\n"
    "# abuse.ch URLhaus Database Dump (CSV)                         #\n"
    "# Last updated: 2026-09-13 13:43:27 (UTC)                      #\n"
    "####\n"
    '"3915965","2026-09-13 13:43:27","http://fingerprint-veri.info/","offline","","malware_download","ClickFix","https://urlhaus.abuse.ch/url/3915965/","ilmari"\n'
    '"3915964","2026-09-13 13:43:26","http://42.229.169.27:32848/Mozi.m","online","2026-09-13 13:43:26","malware_download","elf,iot,Mozi","https://urlhaus.abuse.ch/url/3915964/","HoneyLabs"\n'
)


@pytest.fixture()
def feed() -> ThreatIntelFeed:
    f = ThreatIntelFeed()
    assert f.load_csv(URLHAUS_SAMPLE) == 2
    return f


def test_feed_parses_real_headerless_urlhaus_dump() -> None:
    f = ThreatIntelFeed()
    assert f.load_csv(URLHAUS_REAL_DUMP) == 2
    assert f.lookup("fingerprint-veri.info") is not None
    assert f.lookup("42.229.169.27:32848") is not None
    assert f.lookup("clean.example.org") is None


def test_feed_parses_hosts_case_insensitively(feed: ThreatIntelFeed) -> None:
    assert feed.lookup("evil.example.com") is not None
    assert feed.lookup("EVIL.EXAMPLE.COM") is not None
    assert feed.lookup("bad-host.io:8080") is not None
    assert feed.lookup("benign.example.org") is None


def test_feed_round_trip_and_staleness(tmp_path: Path, feed: ThreatIntelFeed) -> None:
    feed.save(tmp_path / "feed.json")
    restored = ThreatIntelFeed.load(tmp_path / "feed.json")
    assert len(restored) == 2
    assert not restored.is_stale()
    stale = ThreatIntelFeed.load(tmp_path / "missing.json")
    assert len(stale) == 0 and stale.is_stale()


def test_evaluate_hosts_verdicts(feed: ThreatIntelFeed) -> None:
    hit = evaluate_hosts(feed, ["h1", "evil.example.com"])
    assert hit is not None and hit.known_malicious
    assert hit.matches == ["evil.example.com"]
    clean = evaluate_hosts(feed, ["h1", "h2"])
    assert clean is not None and not clean.known_malicious
    assert evaluate_hosts(ThreatIntelFeed(), ["evil.com"]) is None  # no feed -> no verdict


def _state(minute: int, dests: list[str]) -> NetworkState:
    start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=minute)
    return NetworkState(
        window_start=start,
        window_end=start + timedelta(minutes=1),
        features={"bytes": 25000.0, "flow_event_count": 8.0},
        entities=["h1", *dests],
        edge_summary=[
            {"source": "h1", "destination": d, "count": 2.0, "bytes": 1000.0} for d in dests
        ],
        coverage={"flow": True, "packet": False},
        source_ids=[],
    )


BENIGN = tuple(_state(i, ["server-03"]) for i in range(5))


def test_intel_enrichment_raises_c2_and_exfil(feed: ThreatIntelFeed) -> None:
    cur = _state(5, ["evil.example.com"])
    base = run_all_detectors(cur, BENIGN, DetectorSet())
    enriched = run_all_detectors(cur, BENIGN, DetectorSet(), threat_feed=feed)
    by = lambda findings, t: [f for f in findings if f.attack_type == t][0]  # noqa: E731
    assert by(base, "command_and_control").probability == 0.0
    assert by(enriched, "command_and_control").is_alert
    assert by(enriched, "command_and_control").probability == 0.85
    assert by(enriched, "exfiltration").probability >= 0.9
    assert any("list evidence" in w for w in by(enriched, "command_and_control").warnings)


def test_no_feed_leaves_findings_unchanged() -> None:
    cur = _state(5, ["evil.example.com"])
    with_feed = run_all_detectors(cur, BENIGN, DetectorSet(), threat_feed=ThreatIntelFeed())
    without = run_all_detectors(cur, BENIGN, DetectorSet())
    assert [f.probability for f in with_feed] == [f.probability for f in without]


def test_bootstrap_key_registers_admin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from trajectory.auth import ApiKeyStore

    store = ApiKeyStore(tmp_path / "keys.jsonl")
    monkeypatch.setenv("SENTINEL_BOOTSTRAP_KEY", "sent_test_bootstrap_key_000")

    # Re-registering the same bootstrap key is idempotent at authenticate().
    store.register_raw("sent_test_bootstrap_key_000", "admin", label="bootstrap")
    store.register_raw("sent_test_bootstrap_key_000", "admin", label="bootstrap")
    record = store.authenticate("sent_test_bootstrap_key_000")
    assert record.role == "admin"


def test_create_app_bootstrap_env_grants_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full deployment path: env bootstrap key -> authorized API access."""
    from fastapi.testclient import TestClient

    from trajectory.api import create_app
    from trajectory.baseline import save_baseline_artifacts, train_baseline
    from trajectory.config import BaselineConfig
    from trajectory.predict import DECISION_THRESHOLD
    from trajectory.synthetic import generate_labelled_states
    from trajectory.targets import build_sequence_samples, make_split_manifest

    scenarios = [f"boot{i}" for i in range(5)]
    labelled = generate_labelled_states(scenarios, seed=61, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(scenarios, seed=61)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=61,
    )
    save_baseline_artifacts(run, tmp_path / "baseline")

    monkeypatch.setenv("SENTINEL_BOOTSTRAP_KEY", "sent_env_bootstrap_admin")
    app = create_app(tmp_path / "baseline", auth_dir=tmp_path / "auth")
    client = TestClient(app)
    headers = {"X-API-Key": "sent_env_bootstrap_admin"}
    assert client.get("/model", headers=headers).status_code == 200
    assert client.get("/model").status_code == 401
