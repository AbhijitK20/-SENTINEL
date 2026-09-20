"""Shared filesystem paths for the vulnerable demo app.

Defaults are repo-relative so the app runs standalone from the repo root;
docker-compose overrides them to the shared ``/logs`` volume.
"""

from __future__ import annotations

import os
from pathlib import Path

ACCESS_LOG = Path(os.environ.get("SENTINEL_ACCESS_LOG", "apps/vulnerable/access.log"))
BLOCKLIST = Path(os.environ.get("SENTINEL_BLOCKLIST", "apps/vulnerable/blocklist.jsonl"))
