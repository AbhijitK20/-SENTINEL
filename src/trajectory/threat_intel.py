"""Keyless threat-intelligence feeds (roadmap Phase 4/6 enrichment).

Loads free indicator feeds (abuse.ch URLhaus-style CSV: no API key, free for
infrastructure-defense use) and answers one question for the detectors: is
this destination known-malicious?

Every indicator keeps provenance (feed name, first/last seen, list membership)
and an expiry — indicators age out rather than being trusted forever. Feeds
are evidence, not verdicts: presence on a list raises suspicion and is fused
with behavioral signals, never replaces them.
"""

from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

THREAT_INTEL_VERSION = "threat-intel-v1"
DEFAULT_TTL_HOURS = 24.0
DEFAULT_MAX_INDICATORS = 50_000


@dataclass(frozen=True)
class Indicator:
    """One known-malicious destination from a feed."""

    value: str
    feed: str
    list_type: str  # e.g. "malware_download" for URLhaus payload hosts
    first_seen_utc: str
    last_seen_utc: str
    loaded_at: float


@dataclass
class ThreatIntelFeed:
    """In-memory indicator set loaded from a URLhaus-format CSV.

    URLhaus CSV format (https://urlhaus.abuse.ch/): header comment line, then
    ``id,dateadded,url,url_status,threat,tags,urlhaus_reference``. We index the
    host:port portion of each URL. Lookup is O(1); the set is bounded by
    ``max_indicators`` (most-recent wins).
    """

    max_indicators: int = DEFAULT_MAX_INDICATORS
    ttl_hours: float = DEFAULT_TTL_HOURS
    indicators: dict[str, Indicator] = field(default_factory=dict)
    loaded_at: float = 0.0
    source: str = ""

    # ── loading ──────────────────────────────────────────────────────
    def load_csv(self, text: str, *, feed: str = "urlhaus") -> int:
        """Parse a URLhaus-format CSV body; returns the indicator count.

        Two accepted layouts (both observed in the wild):
        - the legacy headered form ``id,dateadded,url,...``
        - the current headerless dump: a ``#`` banner, then 9 quoted columns
          with the URL in position 3 (the real https://urlhaus.abuse.ch
          /downloads/csv/ payload, served as a ZIP containing csv.txt).
        """
        lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
        if not lines:
            return 0
        count = 0
        for row in _csv_rows(lines):
            url = (row.get("url") or "").strip()
            if "://" not in url:
                # Real URLhaus rows always carry a scheme; anything else is
                # noise (banner remnants, malformed rows) and is never an
                # indicator.
                continue
            host = _host_of(url)
            if not host:
                continue
            self.indicators[host] = Indicator(
                value=host,
                feed=feed,
                list_type=(row.get("threat") or "unknown").strip(),
                first_seen_utc=(row.get("dateadded") or "").strip(),
                last_seen_utc=(row.get("dateadded") or "").strip(),
                loaded_at=time.time(),
            )
            count += 1
            if len(self.indicators) >= self.max_indicators:
                break
        self.loaded_at = time.time()
        self.source = feed
        return count

    def save(self, path: Path) -> None:
        """Persist the indicator set so restarts don't re-download."""
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": THREAT_INTEL_VERSION,
            "source": self.source,
            "loaded_at": self.loaded_at,
            "indicators": [
                {
                    "value": i.value,
                    "feed": i.feed,
                    "list_type": i.list_type,
                    "first_seen_utc": i.first_seen_utc,
                    "last_seen_utc": i.last_seen_utc,
                    "loaded_at": i.loaded_at,
                }
                for i in self.indicators.values()
            ],
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> ThreatIntelFeed:
        """Restore a previously saved feed; empty feed when absent/corrupt."""
        feed = cls()
        if not path.exists():
            return feed
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return feed
        feed.source = payload.get("source", "")
        feed.loaded_at = float(payload.get("loaded_at", 0.0))
        for item in payload.get("indicators", []):
            indicator = Indicator(
                value=item["value"],
                feed=item["feed"],
                list_type=item["list_type"],
                first_seen_utc=item["first_seen_utc"],
                last_seen_utc=item["last_seen_utc"],
                loaded_at=float(item["loaded_at"]),
            )
            feed.indicators[indicator.value] = indicator
        return feed

    # ── freshness and lookup ─────────────────────────────────────────
    def age_hours(self) -> float | None:
        """Hours since the feed was loaded; None when never loaded."""
        if self.loaded_at == 0.0:
            return None
        return (time.time() - self.loaded_at) / 3600.0

    def is_stale(self) -> bool:
        """True when the feed was never loaded or is older than the TTL."""
        age = self.age_hours()
        return age is None or age > self.ttl_hours

    def __len__(self) -> int:
        return len(self.indicators)

    def lookup(self, host: str) -> Indicator | None:
        """Known-malicious verdict for a host; None when unknown."""
        return self.indicators.get(host.strip().lower())


def _host_of(url: str) -> str:
    """Extract a lowercase host[:port] from a URL."""
    text = url.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0]


# Column layout of the current headerless URLhaus dump (csv.txt inside the ZIP):
# id, dateadded, url, url_status, threat, tags, urlhaus_reference, reporter —
# position 2 (0-based) is the URL, same column as the legacy headered form.
_URLHAUS_COLUMNS = (
    "id",
    "dateadded",
    "url",
    "url_status",
    "threat",
    "tags",
    "urlhaus_reference",
    "reporter",
)


def _csv_rows(lines: list[str]) -> list[dict[str, str]]:
    """Dict rows for both headered and headerless URLhaus CSV layouts.

    Detection rule: a first line that contains ``url``, a comma, and no
    quotes is treated as a legacy header row (DictReader path). Anything
    else is the current headerless dump, whose quoted positional columns
    are mapped onto the known URLhaus layout.
    """
    first = lines[0]
    looks_headered = "url" in first.lower() and "," in first and '"' not in first
    if looks_headered:
        return list(csv.DictReader(io.StringIO("\n".join(lines))))
    # Headerless dump: map positional columns onto the known layout.
    rows: list[dict[str, str]] = []
    for line in lines:
        fields = next(csv.reader([line]))
        if len(fields) < 3:
            continue
        rows.append(dict(zip(_URLHAUS_COLUMNS, fields, strict=False)))
    return rows


@dataclass(frozen=True)
class IntelVerdict:
    """Threat-intel verdict attached to a finding as evidence."""

    known_malicious: bool
    matches: list[str]
    feed: str
    list_type: str
    warning: str = ""


def evaluate_hosts(
    feed: ThreatIntelFeed,
    hosts: list[str],
) -> IntelVerdict | None:
    """Check hosts against the feed; None verdict when the feed is absent/stale.

    A stale feed still matches (better than nothing) but carries a warning —
    its indicators may be outdated, so the verdict is degraded evidence.
    """
    if len(feed) == 0:
        return None
    matches = sorted({h for h in hosts if feed.lookup(h)})
    if not matches:
        return IntelVerdict(known_malicious=False, matches=[], feed=feed.source, list_type="-")
    warning = ""
    if feed.is_stale():
        warning = f"threat-intel feed is stale ({feed.age_hours():.1f}h old) — degraded evidence"
    return IntelVerdict(
        known_malicious=True,
        matches=matches,
        feed=feed.source,
        list_type=matches and feed.lookup(matches[0]).list_type or "unknown",
        warning=warning,
    )


__all__ = [
    "Indicator",
    "IntelVerdict",
    "THREAT_INTEL_VERSION",
    "ThreatIntelFeed",
    "evaluate_hosts",
]
