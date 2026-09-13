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


def _lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _parse_ts(raw: str) -> datetime | None:
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None
