# SPDX-License-Identifier: Apache-2.0
"""Phase 2 telemetry adapters (stubs): DNS and auth logs -> UnifiedEvent.

These adapters demonstrate the multi-telemetry normalization path the
enterprise roadmap requires. They parse simple line formats and emit
UnifiedEvent records with explicit provenance; they are stubs, not validated
ingestion for production log dialects.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from trajectory.schemas import UnifiedEvent

DNS_EVENT_TYPE = "dns_query"
AUTH_EVENT_TYPE = "auth_event"


def parse_dns_log(
    path: Path,
    *,
    origin: datetime | None = None,
) -> tuple[UnifiedEvent, ...]:
    """Parse lines like ``2026-01-01T00:00:00 client.example 8.8.8.8 evil.com``.

    Columns: timestamp, client, resolver, queried domain. A ``tunnel`` marker
    column (optional 5th) flags high-entropy domains for the future C2
    detector.
    """
    events: list[UnifiedEvent] = []
    for index, line in enumerate(_lines(path)):
        parts = line.split()
        if len(parts) < 4:
            continue
        ts = _parse_ts(parts[0])
        if ts is None:
            base = origin or datetime(2026, 1, 1, tzinfo=UTC)
            ts = base + timedelta(seconds=index)
        client, resolver, domain = parts[1], parts[2], parts[3]
        suspicious = len(parts) > 4 and parts[4] == "tunnel"
        events.append(
            UnifiedEvent(
                event_id=f"dns:{index}",
                timestamp=ts,
                source_entity=client,
                destination_entity=resolver,
                event_type=DNS_EVENT_TYPE,
                features={
                    "domain_length": float(len(domain)),
                    "dns_tunnel_marker": 1.0 if suspicious else 0.0,
                },
                source_format="dns_log_stub",
                provenance=str(path),
            )
        )
    return tuple(events)


def parse_auth_log(
    path: Path,
    *,
    origin: datetime | None = None,
) -> tuple[UnifiedEvent, ...]:
    """Parse lines like ``2026-01-01T00:00:00 host-01 auth-service FAILED bob``.

    Columns: timestamp, source host, auth target, result (FAILED|OK), account.
    Emits one event per line with ``failed_auth`` 1.0/0.0 so the credential
    detector consumes them without change.
    """
    events: list[UnifiedEvent] = []
    for index, line in enumerate(_lines(path)):
        parts = line.split()
        if len(parts) < 5:
            continue
        ts = _parse_ts(parts[0])
        if ts is None:
            base = origin or datetime(2026, 1, 1, tzinfo=UTC)
            ts = base + timedelta(seconds=index)
        source, target, result = parts[1], parts[2], parts[3]
        events.append(
            UnifiedEvent(
                event_id=f"auth:{index}",
                timestamp=ts,
                source_entity=source,
                destination_entity=target,
                event_type=AUTH_EVENT_TYPE,
                features={
                    "failed_auth": 1.0 if result.upper() == "FAILED" else 0.0,
                    "protocol": 88.0,
                },
                source_format="auth_log_stub",
                provenance=str(path),
            )
        )
    return tuple(events)


SYSLOG_SOURCE_FORMAT = "syslog"

# Feature keys the state builder and detectors already consume. Everything
# else a sensor includes is preserved verbatim, so new signals need no
# parser change.
SYSLOG_NUMERIC_FEATURES = (
    "bytes",
    "packets",
    "payload_size",
    "retransmission",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "failed_auth",
    "destination_port",
    "source_port",
    "domain_length",
    "dns_tunnel_marker",
)


def parse_syslog_line(
    line: str,
    *,
    index: int = 0,
    provenance: str = "syslog-tail",
    fallback_timestamp: datetime | None = None,
) -> UnifiedEvent | None:
    """Parse one syslog-style line into a :class:`UnifiedEvent` (or None).

    Format: ``<ISO-8601 timestamp> <host> <app> k=v k=v ...``

    Recognized keys (see :data:`SYSLOG_NUMERIC_FEATURES`) become numeric
    features; ``src``/``dst`` set the event entities. ``failed_auth=yes/true/1``
    maps to the ``failed_auth`` feature the credential detector consumes.
    Timestamps may be Unix epoch seconds. Unparseable lines return None so a
    tailing reader can skip noise without dying.
    """
    text = line.strip()
    if not text:
        return None
    parts = text.split()
    if len(parts) < 3:
        return None
    raw_ts, host, app = parts[0], parts[1], parts[2]
    ts = _parse_ts(raw_ts) or _parse_epoch(raw_ts) or fallback_timestamp
    if ts is None:
        return None

    source_entity = host
    destination_entity = app
    features: dict[str, float] = {}
    for token in parts[3:]:
        if "=" not in token:
            continue
        key, _, raw_value = token.partition("=")
        key = key.strip().lower()
        value = raw_value.strip().strip('"')
        if key in ("src", "source"):
            source_entity = value
            continue
        if key in ("dst", "dest", "target"):
            destination_entity = value
            continue
        if key == "failed_auth":
            lowered = value.lower()
            if lowered in ("yes", "true", "1"):
                features["failed_auth"] = 1.0
            elif lowered in ("no", "false", "0"):
                features["failed_auth"] = 0.0
            continue
        try:
            features[key] = float(value)
        except ValueError:
            continue
    if not features:
        features["bytes"] = 0.0
    return UnifiedEvent(
        event_id=f"syslog:{index}",
        timestamp=ts,
        source_entity=source_entity,
        destination_entity=destination_entity,
        event_type="flow",
        features=features,
        source_format=SYSLOG_SOURCE_FORMAT,
        provenance=provenance,
    )


def _parse_epoch(raw: str) -> datetime | None:
    """Parse a Unix-epoch timestamp string if it is one."""
    try:
        return datetime.fromtimestamp(float(raw), tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None


def _lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_ts(raw: str) -> datetime | None:
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None
