"""Flow CSV ingestion and normalization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from trajectory.schemas import UnifiedEvent

REQUIRED_COLUMNS = {
    "timestamp",
    "source_entity",
    "destination_entity",
    "source_port",
    "destination_port",
    "protocol",
    "bytes",
    "packets",
    "duration",
}
OPTIONAL_COLUMNS = {
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "iat_mean",
    "iat_variance",
    "iat_max",
    "bidirectional_ratio",
}


@dataclass(frozen=True)
class FeatureCoverage:
    """Feature availability reported for one ingestion run."""

    total_rows: int
    flow_features: tuple[str, ...]
    missing_optional_features: tuple[str, ...]
    packet_features_available: bool


@dataclass(frozen=True)
class FlowIngestionResult:
    """Normalized events and coverage metadata from a flow CSV."""

    events: tuple[UnifiedEvent, ...]
    coverage: FeatureCoverage


def read_flow_csv(path: str | Path) -> FlowIngestionResult:
    """Read a canonical flow CSV and convert rows into unified events."""
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Flow CSV does not exist: {csv_path}")

    frame = pd.read_csv(csv_path)
    missing = sorted(REQUIRED_COLUMNS - set(frame.columns))
    if missing:
        raise ValueError(f"Flow CSV is missing required columns: {', '.join(missing)}")
    if frame.empty:
        raise ValueError("Flow CSV contains no data rows")

    timestamps = pd.to_datetime(frame["timestamp"], utc=True, errors="coerce")
    if timestamps.isna().any():
        bad_rows = (timestamps.isna()).to_numpy().nonzero()[0].tolist()
        raise ValueError(f"Invalid timestamp values at zero-based rows: {bad_rows}")

    numeric_columns = [
        "source_port",
        "destination_port",
        "bytes",
        "packets",
        "duration",
        *sorted(OPTIONAL_COLUMNS - {"bidirectional_ratio"}),
        "bidirectional_ratio",
    ]
    for column in set(numeric_columns).intersection(frame.columns):
        values = pd.to_numeric(frame[column], errors="coerce")
        if values.isna().any():
            bad_rows = values.isna().to_numpy().nonzero()[0].tolist()
            raise ValueError(f"Invalid numeric values in '{column}' at rows: {bad_rows}")
        frame[column] = values

    events: list[UnifiedEvent] = []
    optional_cols = sorted(OPTIONAL_COLUMNS.intersection(frame.columns))
    frame = frame.reset_index(drop=True)
    ts_array = timestamps.to_numpy()
    source_entities = frame["source_entity"].to_numpy(dtype=str)
    dest_entities = frame["destination_entity"].to_numpy(dtype=str)
    protocols = frame["protocol"].to_numpy()
    tcp_flags = frame["tcp_flags"].to_numpy() if "tcp_flags" in frame.columns else [""] * len(frame)
    source_ports = frame["source_port"].to_numpy(dtype=float)
    dest_ports = frame["destination_port"].to_numpy(dtype=float)
    bytes_arr = frame["bytes"].to_numpy(dtype=float)
    packets_arr = frame["packets"].to_numpy(dtype=float)
    duration_arr = frame["duration"].to_numpy(dtype=float)
    optional_arrays = {col: frame[col].to_numpy(dtype=float) for col in optional_cols}

    for i in range(len(frame)):
        features = {col: float(optional_arrays[col][i]) for col in optional_cols}
        features.update(
            {
                "source_port": float(source_ports[i]),
                "destination_port": float(dest_ports[i]),
                "bytes": float(bytes_arr[i]),
                "packets": float(packets_arr[i]),
                "duration": float(duration_arr[i]),
            }
        )
        features["protocol"] = float(_protocol_number(protocols[i]))
        features["tcp_flags"] = float(_flag_mask(tcp_flags[i]))
        events.append(
            UnifiedEvent(
                event_id=f"{csv_path.name}:{i + 2}",
                timestamp=ts_array[i].to_pydatetime(),
                source_entity=source_entities[i],
                destination_entity=dest_entities[i],
                event_type="flow",
                features=features,
                source_format="csv",
                provenance=f"{csv_path}:{i + 2}",
            )
        )

    present_optional = tuple(sorted(OPTIONAL_COLUMNS.intersection(frame.columns)))
    return FlowIngestionResult(
        events=tuple(events),
        coverage=FeatureCoverage(
            total_rows=len(frame),
            flow_features=tuple(sorted(REQUIRED_COLUMNS | set(present_optional))),
            missing_optional_features=tuple(sorted(OPTIONAL_COLUMNS - set(present_optional))),
            packet_features_available=False,
        ),
    )


def _protocol_number(value: object) -> int:
    protocols = {"tcp": 6, "udp": 17, "icmp": 1}
    if isinstance(value, str) and value.strip().lower() in protocols:
        return protocols[value.strip().lower()]
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Unsupported protocol value: {value!r}") from error


def _flag_mask(value: object) -> int:
    flags = {flag.strip().upper() for flag in str(value).replace(",", " ").split() if flag.strip()}
    bits = {"FIN": 1, "SYN": 2, "RST": 4, "PSH": 8, "ACK": 16, "URG": 32}
    unknown = flags - bits.keys()
    if unknown:
        raise ValueError(f"Unsupported TCP flag values: {', '.join(sorted(unknown))}")
    return sum(bits[flag] for flag in flags)
