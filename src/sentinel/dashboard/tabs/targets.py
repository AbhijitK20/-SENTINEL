"""Monitor the lab targets SENTINEL is pointed at.

Shows which attack target is configured, whether it answers, and how the local
lab services are doing. Read-only: nothing here starts or stops an attack.

Like ``alerts.py``, this is a network-touching module excluded from the
offline-first rule - a reachability monitor cannot answer without a socket. It
is excluded by *filename* only; the exclusion is asserted in
``tests/test_offline.py`` so it cannot widen unnoticed.
"""

from __future__ import annotations

import os
import socket
import time
from urllib.parse import urlparse

import streamlit as st

DEFAULT_TARGET = "http://localhost:8888"
FRONTEND_PORTS = {"3002": "Idurar frontend (browser)"}


def _probe_host(host: str, port: int, timeout: float = 2.0) -> tuple[bool, float | None]:
    """Return (reachable, latency_ms) for a TCP connect to host:port."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.perf_counter() - started) * 1000.0
    except OSError:
        return False, None


def _configured_target() -> tuple[str, str, int]:
    """Return (url, host, port) for the attack target this console fires at."""
    url = os.environ.get("SENTINEL_DEMO_TARGET", DEFAULT_TARGET)
    host = os.environ.get("SENTINEL_TARGET_HOST") or urlparse(url).hostname or "localhost"
    port = int(os.environ.get("SENTINEL_TARGET_PORT") or urlparse(url).port or 8888)
    return url, host, port


def _lab_targets() -> list[tuple[str, str, int, str]]:
    """Return (label, host, port, note) for each optional local lab service."""
    rows = [("Idurar backend", "idurar-target", 8888, "Mongo-backed ERP under attack")]
    for port, note in FRONTEND_PORTS.items():
        rows.append((f"Idurar frontend :{port}", "localhost", int(port), note))
    return rows


def target_rows() -> list[dict]:
    """Build the monitor table. Split out so it is testable without Streamlit."""
    url, host, port = _configured_target()
    up, latency = _probe_host(host, port)
    rows = [
        {
            "role": "Attack target",
            "endpoint": f"{url} ({host}:{port})",
            "status": "up" if up else "down",
            "latency_ms": round(latency, 1) if latency is not None else None,
            "note": "what the Force Attack buttons hit",
        }
    ]
    for label, lhost, lport, note in _lab_targets():
        l_up, l_latency = _probe_host(lhost, lport)
        rows.append(
            {
                "role": label,
                "endpoint": f"{lhost}:{lport}",
                "status": "up" if l_up else "down",
                "latency_ms": round(l_latency, 1) if l_latency is not None else None,
                "note": note,
            }
        )
    return rows


def render() -> None:
    st.subheader("Target monitor")
    st.caption("What SENTINEL is watching, and whether it is answering right now.")

    rows = target_rows()
    st.dataframe(
        rows,
        use_container_width=True,
        hide_index=True,
        column_config={
            "role": "Role",
            "endpoint": "Endpoint",
            "status": "Status",
            "latency_ms": st.column_config.NumberColumn("Latency (ms)", format="%.1f"),
            "note": "Note",
        },
    )

    target_up = rows[0]["status"] == "up"
    if not target_up:
        st.warning(
            "The attack target is not reachable, so Force Attack will not send real "
            "traffic. Start the lab with `docker compose --profile lab up -d`."
        )
    else:
        st.success("Attack target is up — Force Attack will send real traffic.")


__all__ = ["render", "target_rows"]
