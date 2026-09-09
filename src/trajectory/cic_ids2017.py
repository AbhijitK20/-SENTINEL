"""CIC-IDS2017 dataset adapter.

Converts CICFlowMeter CSV exports of CIC-Flow-Meter (the dataset's standard
per-flow CSVs) into the project's unified-event contract, then derives
window-level labels with documented, versioned rules.

Dataset identity and licence
----------------------------

- Name: CIC-IDS2017 (Canadian Institute for Cybersecurity, University of
  New Brunswick).
- Access: https://www.unb.ca/cic/datasets/ids-2017.html — the dataset is
  publicly downloadable for research use; the licence terms on that page apply
  and must be reviewed before redistribution of derived data.
- This adapter never bundles the dataset. Tests use small synthetic fixtures
  in the same schema; committing real captures or derived rows is forbidden.

Label derivation (documented and versioned)
-------------------------------------------

CICFlowMeter exports one row per bidirectional flow with the label column
``Label`` (e.g. ``BENIGN``, ``DoS Hulk``, ``PortScan``). Rules:

1. ``BENIGN`` → stage ``Benign``, no infiltration.
2. Any other label maps through STAGE_RULES below to a stage in the project's
   vocabulary. Unmapped attack labels raise a strict error so silent label
   loss is impossible; extend STAGE_RULES deliberately when new labels appear.
3. A window is labelled by the stage of its flows with the documented
   precedence (infiltration stages dominate), matching the replay labelling
   convention of labelling by the window end.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from trajectory.schemas import NetworkState, StateLabel, UnifiedEvent
from trajectory.state_builder import build_network_states
from trajectory.targets import LabelledState, make_state_key

ADAPTER_VERSION = "cic-ids2017-adapter-v1"
DATASET_ID = "CIC-IDS2017"
DATASET_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"

# Project stage vocabulary (see MITRE_MAPPING_PLAN.md). Each attack label maps
# to (project stage, infiltration flag). Keep sorted for review.
STAGE_RULES: dict[str, tuple[str, bool]] = {
    "benign": ("Benign", False),
    "ftp-patator": ("Credential Access", True),
    "ssh-patator": ("Credential Access", True),
    "dos slowhttptest": ("Denial of Service", True),
    "dos slowloris": ("Denial of Service", True),
    "dos goldeneye": ("Denial of Service", True),
    "dos hulk": ("Denial of Service", True),
    "heartbeat": ("Command and Control", True),
    "infiltration": ("Lateral Movement", True),
    "infiltration - nmap portscan": ("Reconnaissance", False),
    "infiltration - dropping file (mitm)": ("Lateral Movement", True),
    "bot": ("Command and Control", True),
    "portscan": ("Reconnaissance", False),
    "portscan - nmap fin": ("Reconnaissance", False),
    "portscan - Syn": ("Reconnaissance", False),
    "portscan - udp": ("Reconnaissance", False),
    "web attack - brute force": ("Initial Access", True),
    "web attack - brute forcing": ("Initial Access", True),
    "web attack - xss": ("Initial Access", True),
    "web attack - sql injection": ("Initial Access", True),
}


class AdapterError(ValueError):
    """Raised for unmapped labels or unusable rows; never silently skipped."""


class AdapterStats(BaseModel):
    """Provenance summary for one adapter run."""

    model_config = ConfigDict(extra="forbid")

    adapter_version: str = ADAPTER_VERSION
    dataset_id: str = DATASET_ID
    source_files: list[str]
    rows_read: int = Field(ge=0)
    rows_converted: int = Field(ge=0)
    rows_rejected: int = Field(ge=0)
    rows_void: int = Field(default=0, ge=0)
    unmapped_labels: list[str] = Field(default_factory=list)
    windows_built: int = Field(default=0, ge=0)


def map_label(raw_label: str) -> tuple[str, bool]:
    """Map a CICFlowMeter ``Label`` value to (stage, infiltration).

    Real CSVs use en-dashes (``Web Attack \u2013 XSS``) and mixed case; the
    value is normalized to lowercase ASCII-hyphen form before lookup.
    """
    normalized = (
        raw_label.strip()
        .lower()
        .replace("\u2013", "-")  # en-dash used by the real CSVs
        .replace("\u2014", "-")  # em-dash variant
        .replace("\u0096", "-")  # latin-1 residue of cp1252 0x96
    )
    rule = STAGE_RULES.get(normalized)
    if rule is None:
        raise AdapterError(
            f"unmapped CIC-IDS2017 label {raw_label!r}; extend STAGE_RULES "
            "deliberately instead of dropping the label"
        )
    return rule


def parse_flow_timestamp(value: str) -> datetime:
    """Parse CICFlowMeter's ``Timestamp`` column.

    Documented dataset defects handled here (verified against the published
    UNB capture schedule and the literature):

    - Dates are day-first: ``6/7/2017`` = 6 July.
    - Times are written on a 12-hour clock without AM/PM. Working days run
      8:00-17:00, so hours 1-7 can only be PM and are shifted +12; hours
      8-11 are AM, 12 is noon. This rule holds for morning files, afternoon
      files, and the mixed Tuesday file (9-12 then 1-5).
    """
    for fmt in (
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S.%f",
        "%d/%m/%Y %H:%M",
    ):
        try:
            parsed = datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
        if parsed.hour < 8:
            parsed = parsed.replace(hour=parsed.hour + 12)
        return parsed.replace(tzinfo=UTC)
    raise AdapterError(f"unparseable flow timestamp: {value!r}")


# Real TrafficLabelling headers carry leading spaces and singular/plural
# variants; canonicalize before validation. Keys are stripped header names.
COLUMN_ALIASES = {
    "Total Fwd Packets": "Total Fwd Packet",
    "Total Backward Packets": "Total Bwd packets",
    "Total Length of Fwd Packets": "Total Length of Fwd Packet",
    "Total Length of Bwd Packets": "Total Length of Bwd Packet",
}


def canonicalize_header(fieldnames: list[str]) -> list[str]:
    """Strip whitespace and apply documented column aliases."""
    return [COLUMN_ALIASES.get(name.strip(), name.strip()) for name in fieldnames]


def load_flow_csv(
    path: str | Path,
    *,
    scenario_id: str | None = None,
    time_window: tuple[datetime, datetime] | None = None,
) -> list[UnifiedEvent]:
    """Read one CICFlowMeter CSV into unified events.

    ``scenario_id`` defaults to the CSV stem. Rows with unmapped labels raise
    ``AdapterError``; conversion statistics are available via
    :func:`load_flow_csv_with_stats`. When ``time_window`` is given, only rows
    whose timestamp falls inside ``[start, end]`` are converted; rows outside
    are skipped without counting as rejections.
    """
    events, _ = load_flow_csv_with_stats(path, scenario_id=scenario_id, time_window=time_window)
    return events


def load_flow_csv_with_stats(
    path: str | Path,
    *,
    scenario_id: str | None = None,
    time_window: tuple[datetime, datetime] | None = None,
) -> tuple[list[UnifiedEvent], AdapterStats]:
    """Read one CICFlowMeter CSV into unified events plus adapter statistics.

    Strict mode: any unmapped label aborts the conversion with
    ``AdapterError`` after the full pass, so silent label loss is impossible.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"CIC-IDS2017 CSV not found: {csv_path}")
    scenario = scenario_id or csv_path.stem

    events: list[UnifiedEvent] = []
    rows_read = 0
    rows_rejected = 0
    rows_void = 0
    unmapped: list[str] = []
    with _open_csv_text(csv_path) as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise AdapterError(f"empty CSV: {csv_path}")
        reader.fieldnames = canonicalize_header(reader.fieldnames)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise AdapterError(f"missing required columns: {sorted(missing)}")
        for row in reader:
            rows_read += 1
            # Documented packaging defect: the Thursday-morning file ships
            # 288,602 appended rows with an empty Label *and* empty Timestamp
            # (mis-split packaging; exactly the afternoon file's row count).
            # They are structurally void — skipped and counted explicitly,
            # never silently: void rows appear in AdapterStats.rows_void.
            if not row.get("Label", "").strip() and not row.get("Timestamp", "").strip():
                rows_void += 1
                continue
            if time_window is not None:
                row_start = parse_flow_timestamp(row["Timestamp"])
                if not (time_window[0] <= row_start <= time_window[1]):
                    continue
            try:
                events.append(_convert_row(row, scenario, rows_read))
            except AdapterError as error:
                rows_rejected += 1
                message = str(error)
                if "unmapped" in message and message not in unmapped:
                    unmapped.append(message)
    if unmapped:
        raise AdapterError(
            f"{len(unmapped)} unmapped CIC-IDS2017 label(s): "
            + "; ".join(unmapped)
            + " — extend STAGE_RULES deliberately instead of dropping rows"
        )

    stats = AdapterStats(
        source_files=[csv_path.name],
        rows_read=rows_read,
        rows_converted=len(events),
        rows_rejected=rows_rejected,
        rows_void=rows_void,
        unmapped_labels=unmapped,
    )
    return events, stats


REQUIRED_COLUMNS = {
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Flow IAT Mean",
    "Label",
}


def _convert_row(row: dict[str, str], scenario_id: str, row_index: int) -> UnifiedEvent:
    label = row.get("Label", "")
    map_label(label)  # strict: unknown labels abort conversion

    start = parse_flow_timestamp(row["Timestamp"])
    duration_us = _positive_float(row, "Flow Duration", default=0.0)

    src_port = _positive_float(row, "Source Port", default=0.0)
    dst_port = _positive_float(row, "Destination Port", default=0.0)

    features = {
        "source_port": src_port,
        "destination_port": dst_port,
        # CICFlowMeter writes Infinity in length columns for zero-payload
        # flows; the documented default is 0 bytes, never a dropped row.
        "bytes": _positive_float(row, "Total Length of Fwd Packet", default=0.0)
        + _positive_float(row, "Total Length of Bwd Packet", default=0.0),
        "packets": _positive_float(row, "Total Fwd Packet", default=0.0)
        + _positive_float(row, "Total Bwd packets", default=0.0),
        "duration": duration_us / 1_000_000.0,
        "flow_iat_mean_ms": _positive_float(row, "Flow IAT Mean", default=0.0),
        "syn_count": _positive_float(row, "SYN Flag Count", default=0.0),
        "ack_count": _positive_float(row, "ACK Flag Count", default=0.0),
        "fin_count": _positive_float(row, "FIN Flag Count", default=0.0),
        "rst_count": _positive_float(row, "RST Flag Count", default=0.0),
        "psh_count": _positive_float(row, "PSH Flag Count", default=0.0),
    }

    return UnifiedEvent(
        # Real Flow IDs are unique per flow; the row index is a documented
        # fallback when the column is blank.
        event_id=(row.get("Flow ID") or "").strip() or f"{scenario_id}:row-{row_index}",
        timestamp=start,
        source_entity=row["Source IP"].strip(),
        destination_entity=row["Destination IP"].strip(),
        event_type="flow",
        features=features,
        source_format="csv",
        provenance=f"{DATASET_ID}:{scenario_id}:{label.strip()}",
    )


def _open_csv_text(csv_path: Path) -> io.StringIO:
    """Open a CICFlowMeter CSV as text, handling the mixed encodings on disk.

    The published archives are inconsistent: most day files are UTF-8 (with a
    BOM in some), while the Thursday-morning file is cp1252 — its labels
    carry a 0x96 en-dash byte (``Web Attack – Brute Force``). cp1252 decodes
    0x96 to the proper en-dash U+2013 which :func:`map_label` normalizes;
    latin-1 is the never-failing last resort (its U+0096 residue is also
    normalized in :func:`map_label`).
    """
    raw = csv_path.read_bytes()
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return io.StringIO(raw.decode(encoding), newline="")
        except UnicodeDecodeError:
            continue
    raise AdapterError(f"undecodable CSV encoding: {csv_path}")


def _positive_float(row: dict[str, str], column: str, *, default: float | None = None) -> float:
    """Parse a CICFlowMeter numeric cell; 'Infinity'/'NaN' use the default."""
    raw = (row.get(column) or "").strip()
    if raw == "" or raw.lower() in {"infinity", "-infinity", "nan"}:
        if default is None:
            raise AdapterError(f"column {column!r} has unusable value {raw!r}")
        return default
    try:
        value = float(raw)
    except ValueError as error:
        raise AdapterError(f"column {column!r} has unusable value {raw!r}") from error
    return value


def build_labelled_states(
    events: list[UnifiedEvent],
    flow_labels: list[tuple[datetime, str]],
    *,
    window_seconds: int,
    stride_seconds: int,
    scenario_id: str,
) -> list[LabelledState]:
    """Build windowed states and derive window labels from per-flow labels.

    ``flow_labels`` carries (flow start timestamp, raw CICFlowMeter label) per
    event order. A window is labelled by the stage of the flows it contains
    with the documented precedence: infiltration stages dominate benign and
    reconnaissance labels inside the same window; the window's *last* deciding
    flow wins ties, mirroring the label-at-window-end convention.
    """
    if len(events) != len(flow_labels):
        raise ValueError("events and flow_labels must have the same length")
    if not events:
        raise ValueError("at least one event is required")

    mapped = [map_label(label) for _, label in flow_labels]

    states = build_network_states(
        events, window_seconds=window_seconds, stride_seconds=stride_seconds
    )
    labelled: list[LabelledState] = []
    for index, state in enumerate(states):
        stage, infiltration = _window_stage(state, events, mapped)
        key = make_state_key(state, index)
        labelled.append(
            LabelledState(
                state_key=key,
                scenario_id=scenario_id,
                state=state,
                label=StateLabel(
                    state_key=key,
                    scenario_id=scenario_id,
                    infiltration=infiltration,
                    attack_stage=stage,
                    label_source="dataset",
                ),
            )
        )
    return labelled


_STAGE_PRECEDENCE = {
    "Benign": 0,
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Credential Access": 3,
    "Command and Control": 4,
    "Denial of Service": 5,
    "Lateral Movement": 6,
}


def _window_stage(
    state: NetworkState, events: list[UnifiedEvent], mapped: list[tuple[str, bool]]
) -> tuple[str, bool]:
    """Precedence-based stage for one window from the flows it contains."""
    window_event_ids = set(state.source_ids)
    stage = "Benign"
    infiltration = False
    best = -1
    for event, (event_stage, event_infiltration) in zip(events, mapped, strict=False):
        if event.event_id not in window_event_ids:
            continue
        rank = _STAGE_PRECEDENCE.get(event_stage, 0)
        if rank >= best:
            best = rank
            stage = event_stage
            infiltration = event_infiltration
    return stage, infiltration


__all__ = [
    "ADAPTER_VERSION",
    "AdapterError",
    "AdapterStats",
    "DATASET_ID",
    "DATASET_URL",
    "REQUIRED_COLUMNS",
    "STAGE_RULES",
    "build_labelled_states",
    "load_flow_csv",
    "load_flow_csv_with_stats",
    "map_label",
    "parse_flow_timestamp",
]
