"""Tests for the target monitor tab."""

from __future__ import annotations

from sentinel.dashboard.tabs import targets


def test_configured_target_reads_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_DEMO_TARGET", "http://idurar-target:8888")
    monkeypatch.delenv("SENTINEL_TARGET_HOST", raising=False)
    monkeypatch.delenv("SENTINEL_TARGET_PORT", raising=False)
    url, host, port = targets._configured_target()
    assert (url, host, port) == ("http://idurar-target:8888", "idurar-target", 8888)


def test_configured_target_env_overrides_url(monkeypatch):
    monkeypatch.setenv("SENTINEL_DEMO_TARGET", "http://ignored:1234")
    monkeypatch.setenv("SENTINEL_TARGET_HOST", "real-host")
    monkeypatch.setenv("SENTINEL_TARGET_PORT", "9999")
    assert targets._configured_target() == ("http://ignored:1234", "real-host", 9999)


def test_probe_host_reports_unreachable():
    up, latency = targets._probe_host("127.0.0.1", 1, timeout=0.2)
    assert up is False
    assert latency is None


def test_target_rows_shape(monkeypatch):
    monkeypatch.setenv("SENTINEL_DEMO_TARGET", "http://127.0.0.1:1")
    monkeypatch.delenv("SENTINEL_TARGET_HOST", raising=False)
    monkeypatch.delenv("SENTINEL_TARGET_PORT", raising=False)
    rows = targets.target_rows()
    # the attack target plus the lab services
    assert len(rows) >= 2
    assert rows[0]["role"] == "Attack target"
    for row in rows:
        assert set(row) == {"role", "endpoint", "status", "latency_ms", "note"}
        assert row["status"] in {"up", "down"}
        assert (row["latency_ms"] is None) == (row["status"] == "down")
