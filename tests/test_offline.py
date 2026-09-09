"""Offline-operation verification (Definition of Done: UI And Demo).

The runtime must not depend on cloud APIs. This test pins the configuration
contract and statically asserts that no network client is imported anywhere
under ``src/trajectory``.
"""

from __future__ import annotations

from pathlib import Path

from trajectory.config import load_settings

SRC = Path(__file__).resolve().parent.parent / "src" / "trajectory"

NETWORK_MODULES = (
    "import requests",
    "import urllib",
    "import httpx",
    "import socket",
    "import aiohttp",
    "import http.client",
    "import boto3",
    "import google.cloud",
)


def test_runtime_is_configured_offline() -> None:
    settings = load_settings("configs/default.yaml")
    assert settings.runtime.offline is True
    assert settings.runtime.device == "cpu"


def test_no_network_imports_in_source() -> None:
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for module in NETWORK_MODULES:
            if module in text:
                offenders.append(f"{path.name}: {module}")
    assert not offenders, f"network clients found in offline source: {offenders}"


def test_no_cloud_urls_in_source() -> None:
    """No https:// API endpoints in runtime source (doc URLs in adapters excluded)."""
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if "https://" in stripped and "unb.ca" not in stripped and "#" in stripped:
                continue
            if "https://api." in stripped or "https://cloud" in stripped:
                offenders.append(f"{path.name}: {stripped[:60]}")
    assert not offenders, f"cloud API endpoints found: {offenders}"
