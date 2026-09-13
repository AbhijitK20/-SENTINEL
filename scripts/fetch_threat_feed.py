"""Fetch a free threat-intel feed (abuse.ch URLhaus) into the local feed file.

Offline-first contract: the SENTINEL runtime (``src/trajectory``) never touches
the network — this script is the out-of-band refresh path that
``DEPLOYMENT.md`` documents. Run it from cron, a compose init container, or by
hand; the API picks the refreshed file up on restart.

Free sources (no key, no payment):
- URLhaus online CSV: https://urlhaus.abuse.ch/downloads/csv/ (malware URL hosts)
- Optional extras via --extra: Spamhaus DROP / Tor exit list (text lists)

Usage:
    uv run python scripts/fetch_threat_feed.py                    # default paths
    uv run python scripts/fetch_threat_feed.py --out my_feed.json # custom output

Exit codes: 0 success (feed saved), 1 fetch failed (stale file kept).
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trajectory.threat_intel import ThreatIntelFeed  # noqa: E402

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv/"
DEFAULT_OUT = Path("reports/threat_intel/feed.json")
TIMEOUT_SECONDS = 30
USER_AGENT = "sentinel-feed-fetcher/1.0 (SIH26153; offline-first refresh)"


def fetch_urlhaus_csv(url: str = URLHAUS_CSV) -> str:
    """Download the URLhaus CSV body; raises on HTTP/network failure.

    abuse.ch serves the CSV as a ZIP archive containing ``csv.txt`` — both the
    plain-CSV and the zipped variants are handled here.
    """
    import io
    import zipfile

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        body = response.read()
    if body[:2] == b"PK":
        archive = zipfile.ZipFile(io.BytesIO(body))
        member = archive.namelist()[0]  # abuse.ch archives contain exactly csv.txt
        return archive.read(member).decode("utf-8", errors="replace")
    return body.decode("utf-8", errors="replace")


def build_feed(csv_text: str, *, feed: str = "urlhaus") -> ThreatIntelFeed:
    """Parse the URLhaus CSV into a bounded indicator feed."""
    threat_feed = ThreatIntelFeed()
    threat_feed.load_csv(csv_text, feed=feed)
    return threat_feed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"output feed JSON path (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--url",
        default=URLHAUS_CSV,
        help="URLhaus-format CSV source URL",
    )
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=None,
        help="refuse to overwrite a feed file younger than this (cron safety)",
    )
    args = parser.parse_args(argv)

    if args.max_age_hours is not None and args.out.exists():
        age_hours = (time.time() - args.out.stat().st_mtime) / 3600.0
        if age_hours < args.max_age_hours:
            print(
                f"feed at {args.out} is {age_hours:.1f}h old (< {args.max_age_hours}h) — keeping it"
            )
            return 0

    print(f"fetching {args.url} ...")
    try:
        csv_text = fetch_urlhaus_csv(args.url)
    except Exception as error:  # noqa: BLE001 - cron script must not crash the host
        print(f"fetch failed: {error}", file=sys.stderr)
        if args.out.exists():
            print(f"keeping previous feed at {args.out}")
        return 1

    threat_feed = build_feed(csv_text)
    if len(threat_feed) == 0:
        print("fetched CSV parsed to zero indicators — refusing to overwrite", file=sys.stderr)
        return 1

    threat_feed.save(args.out)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"saved {len(threat_feed)} indicators to {args.out}")
    print(f"source={threat_feed.source} refreshed_at={stamp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
