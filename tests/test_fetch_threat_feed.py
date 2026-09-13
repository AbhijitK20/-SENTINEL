"""Tests for scripts/fetch_threat_feed.py — network is mocked in every test.

The script is the out-of-band refresh path documented in DEPLOYMENT.md; these
tests pin its parsing, freshness guard, and failure behaviour without any
real HTTP traffic (CI stays offline).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "fetch_threat_feed.py"
spec = importlib.util.spec_from_file_location("fetch_threat_feed", SCRIPT)
fetch_threat_feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch_threat_feed)  # type: ignore[union-attr]

URLHAUS_SAMPLE = (
    "id,dateadded,url,url_status,threat,tags,urlhaus_reference\n"
    '1,2026-09-13 10:00:00 UTC,http://malware.example/payload.exe,online,malware_download,"heodo",ref1\n'
    '2,2026-09-13 11:00:00 UTC,http://bad.host.example:8080/bad,online,malware_download,"mirai",ref2\n'
)


def test_build_feed_parses_urlhaus_hosts() -> None:
    feed = fetch_threat_feed.build_feed(URLHAUS_SAMPLE)
    assert len(feed) == 2
    assert feed.lookup("malware.example") is not None
    assert feed.lookup("bad.host.example:8080") is not None
    assert feed.lookup("clean.example") is None
    assert feed.source == "urlhaus"


def test_main_saves_feed_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(fetch_threat_feed, "fetch_urlhaus_csv", lambda url: URLHAUS_SAMPLE)
    out = tmp_path / "feed.json"
    code = fetch_threat_feed.main(["--out", str(out)])
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["source"] == "urlhaus"
    assert len(payload["indicators"]) == 2


def test_main_fetch_failure_keeps_previous_feed(tmp_path, monkeypatch) -> None:
    def boom(url: str) -> str:
        raise OSError("network down")

    monkeypatch.setattr(fetch_threat_feed, "fetch_urlhaus_csv", boom)
    out = tmp_path / "feed.json"
    old_payload = json.dumps({"source": "old", "loaded_at": 1.0, "indicators": []})
    out.write_text(old_payload, encoding="utf-8")
    code = fetch_threat_feed.main(["--out", str(out)])
    assert code == 1
    # previous content untouched
    assert json.loads(out.read_text(encoding="utf-8"))["source"] == "old"


def test_main_refuses_empty_parse(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(fetch_threat_feed, "fetch_urlhaus_csv", lambda url: "garbage,no,headers\n")
    out = tmp_path / "feed.json"
    code = fetch_threat_feed.main(["--out", str(out)])
    assert code == 1
    assert not out.exists()


def test_max_age_guard_skips_fresh_file(tmp_path, monkeypatch) -> None:
    called = False

    def fail_if_called(url: str) -> str:
        nonlocal called
        called = True
        raise AssertionError("fetch must not run when the guard triggers")

    monkeypatch.setattr(fetch_threat_feed, "fetch_urlhaus_csv", fail_if_called)
    out = tmp_path / "feed.json"
    out.write_text("{}", encoding="utf-8")
    code = fetch_threat_feed.main(["--out", str(out), "--max-age-hours", "24"])
    assert code == 0
    assert called is False
