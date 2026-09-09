"""Tests for the CIC-IDS2017 adapter using synthetic schema fixtures.

No real dataset content is committed; the fixture below only mimics the
CICFlowMeter CSV column layout.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trajectory.cic_ids2017 import (
    ADAPTER_VERSION,
    DATASET_ID,
    AdapterError,
    build_labelled_states,
    load_flow_csv,
    load_flow_csv_with_stats,
    map_label,
    parse_flow_timestamp,
)

COLUMNS = [
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
]


def _row(flow_id: str, ts: str, label: str, **overrides) -> dict[str, str]:
    row = {
        "Flow ID": flow_id,
        "Source IP": "192.168.1.10",
        "Destination IP": "192.168.1.20",
        "Source Port": "41000",
        "Destination Port": "443",
        "Protocol": "6",
        "Timestamp": ts,
        "Flow Duration": "250000",  # microseconds
        "Total Fwd Packet": "10",
        "Total Bwd packets": "12",
        "Total Length of Fwd Packet": "1200",
        "Total Length of Bwd Packet": "3400",
        "FIN Flag Count": "1",
        "SYN Flag Count": "1",
        "RST Flag Count": "0",
        "PSH Flag Count": "2",
        "ACK Flag Count": "11",
        "Flow IAT Mean": "12500",
        "Label": label,
    }
    row.update(overrides)
    return row


def _write_csv(path: Path, rows: list[dict[str, str]], *, columns: list[str] | None = None):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns or COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _fixture_rows() -> list[dict[str, str]]:
    return [
        _row("f1", "03/07/2017 08:56:10", "BENIGN"),
        _row("f2", "03/07/2017 08:56:20", "BENIGN"),
        _row(
            "f3",
            "03/07/2017 08:56:30",
            "PortScan",
            **{"Destination Port": "22", "SYN Flag Count": "1", "RST Flag Count": "1"},
        ),
    ]


def test_map_label_rules_and_rejections() -> None:
    assert map_label("BENIGN") == ("Benign", False)
    assert map_label("portscan") == ("Reconnaissance", False)
    assert map_label(" Infiltration ") == ("Lateral Movement", True)
    assert map_label("DoS Hulk") == ("Denial of Service", True)
    assert map_label("Web Attack Ǘ Brute Forcing".replace("Ǘ", "-")) == ("Initial Access", True)
    with pytest.raises(AdapterError, match="unmapped"):
        map_label("Some Novel Attack")


def test_parse_timestamp_day_first_with_utc() -> None:
    parsed = parse_flow_timestamp("03/07/2017 08:56:10")
    assert parsed.tzinfo is UTC
    assert (parsed.day, parsed.month) == (3, 7)  # day-first, not month-first
    with pytest.raises(AdapterError, match="unparseable"):
        parse_flow_timestamp("not a date")


def test_load_flow_csv_converts_rows(tmp_path: Path) -> None:
    path = tmp_path / "fixture-flows.csv"
    _write_csv(path, _fixture_rows())

    events, stats = load_flow_csv_with_stats(path)

    assert stats.adapter_version == ADAPTER_VERSION
    assert stats.dataset_id == DATASET_ID
    assert stats.rows_read == 3
    assert stats.rows_converted == 3
    assert stats.rows_rejected == 0
    assert len(events) == 3
    first = events[0]
    assert first.event_type == "flow"
    assert first.source_format == "csv"
    # bytes = fwd length + bwd length
    assert first.features["bytes"] == 4600.0
    # packets = fwd + bwd
    assert first.features["packets"] == 22.0
    # duration converted from microseconds to seconds
    assert first.features["duration"] == pytest.approx(0.25)
    assert first.timestamp.isoformat().startswith("2017-07-03T08:56:10")


def test_infinity_lengths_default_to_zero(tmp_path: Path) -> None:
    path = tmp_path / "inf.csv"
    _write_csv(
        path,
        [_row("f1", "03/07/2017 08:56:10", "BENIGN", **{"Total Length of Bwd Packet": "Infinity"})],
    )

    events = load_flow_csv(path)

    assert events[0].features["bytes"] == 1200.0


def test_unmapped_label_rejected_strictly(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    _write_csv(
        path,
        [
            *_fixture_rows()[:2],
            _row("f9", "03/07/2017 08:56:40", "Totally New Attack"),
        ],
    )

    with pytest.raises(AdapterError, match="unmapped"):
        load_flow_csv(path)


def test_missing_required_columns_rejected(tmp_path: Path) -> None:
    path = tmp_path / "short.csv"
    reduced_columns = [c for c in COLUMNS if c != "Label"]
    row_without_label = {
        key: value
        for key, value in _row("f1", "03/07/2017 08:56:10", "BENIGN").items()
        if key != "Label"
    }
    _write_csv(path, [row_without_label], columns=reduced_columns)

    with pytest.raises(AdapterError, match="missing required columns"):
        load_flow_csv(path)


def test_build_labelled_states_precedence(tmp_path: Path) -> None:
    path = tmp_path / "fixture-flows.csv"
    rows = _fixture_rows()
    _write_csv(path, rows)

    events = load_flow_csv(path)
    flow_labels = [(event.timestamp, row["Label"]) for event, row in zip(events, rows, strict=True)]

    labelled = build_labelled_states(
        events,
        flow_labels,
        window_seconds=60,
        stride_seconds=60,
        scenario_id="fixture",
    )

    assert labelled, "windows must be built from fixture events"
    # All fixture flows fall inside one 60s window; PortScan (rank 1) outranks
    # Benign (rank 0), and recon does not flag infiltration.
    combined = labelled[0]
    assert combined.label.attack_stage == "Reconnaissance"
    assert combined.label.infiltration is False
    assert combined.label.label_source == "dataset"


def test_infiltration_stage_dominates(tmp_path: Path) -> None:
    path = tmp_path / "infil.csv"
    rows = [
        _row("f1", "03/07/2017 08:56:10", "BENIGN"),
        _row("f2", "03/07/2017 08:56:30", "Bot"),
    ]
    _write_csv(path, rows)

    events = load_flow_csv(path)
    flow_labels = [(event.timestamp, row["Label"]) for event, row in zip(events, rows, strict=True)]
    labelled = build_labelled_states(
        events,
        flow_labels,
        window_seconds=60,
        stride_seconds=60,
        scenario_id="fixture",
    )

    assert labelled[0].label.attack_stage == "Command and Control"
    assert labelled[0].label.infiltration is True


def test_mismatched_labels_length_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fixture-flows.csv"
    _write_csv(path, _fixture_rows())
    events = load_flow_csv(path)

    with pytest.raises(ValueError, match="same length"):
        build_labelled_states(
            events,
            [(events[0].timestamp, "BENIGN")],
            window_seconds=60,
            stride_seconds=60,
            scenario_id="fixture",
        )


def test_window_datetime_bounds_are_monotonic(tmp_path: Path) -> None:
    path = tmp_path / "fixture-flows.csv"
    rows = _fixture_rows()
    _write_csv(path, rows)
    events = load_flow_csv(path)
    flow_labels = [(event.timestamp, row["Label"]) for event, row in zip(events, rows, strict=True)]

    labelled = build_labelled_states(
        events,
        flow_labels,
        window_seconds=30,
        stride_seconds=15,
        scenario_id="fixture",
    )

    starts = [item.state.window_start for item in labelled]
    assert starts == sorted(starts)
    assert all(isinstance(start, datetime) for start in starts)


def test_pm_clock_rule_matches_published_schedule() -> None:
    """The 12-hour-without-AM/PM defect: hours 1-7 are PM on working days.

    Validated against the published UNB Infiltration window (14:19-15:45 on
    Thursday 2017-07-06): the raw afternoon file contains only hours 1-3.
    """
    assert parse_flow_timestamp("6/7/2017 1:00").hour == 13
    assert parse_flow_timestamp("6/7/2017 2:19").hour == 14
    assert parse_flow_timestamp("6/7/2017 3:45").hour == 15


def test_am_hours_and_noon_are_not_shifted() -> None:
    """Morning files (and Tuesday's mixed 9-12 + 1-5 hours) stay correct."""
    assert parse_flow_timestamp("6/7/2017 9:00").hour == 9
    assert parse_flow_timestamp("6/7/2017 12:00").hour == 12
    assert parse_flow_timestamp("6/7/2017 11:59:59").hour == 11


def test_cp1252_encoding_and_en_dash_labels(tmp_path: Path) -> None:
    """Thursday-morning is cp1252 with a 0x96 en-dash in Web Attack labels."""
    path = tmp_path / "thursday-morning.csv"
    rows = [
        _row("f1", "06/07/2017 9:30:00", "BENIGN"),
        _row("f2", "06/07/2017 10:15:00", "Web Attack \u2013 Brute Force"),
    ]
    payload = (
        ",".join(COLUMNS)
        + "\n"
        + "\n".join(",".join(row[column] for column in COLUMNS) for row in rows)
        + "\n"
    )
    path.write_bytes(payload.encode("cp1252"))

    events = load_flow_csv(path)
    assert len(events) == 2
    assert events[1].provenance.endswith("Web Attack \u2013 Brute Force")


def test_leading_space_headers_and_plural_variants(tmp_path: Path) -> None:
    """Real TrafficLabelling headers carry leading spaces and plural forms."""
    path = tmp_path / "spaced.csv"
    spaced_columns = [f" {name}" for name in COLUMNS]
    rows = _fixture_rows()
    renamed = [{f" {key}": value for key, value in row.items()} for row in rows]
    _write_csv(path, renamed, columns=spaced_columns)
    plural = path.with_name("plural.csv")
    plural_columns = [
        name.replace("Total Fwd Packet", "Total Fwd Packets").replace("Total Backward", "Total Bwd")
        for name in spaced_columns
    ]
    plural_rows = [
        {
            key.replace("Total Fwd Packet", "Total Fwd Packets").replace(
                "Total Backward", "Total Bwd"
            ): value
            for key, value in row.items()
        }
        for row in renamed
    ]
    _write_csv(plural, plural_rows, columns=plural_columns)

    for candidate in (path, plural):
        events = load_flow_csv(candidate)
        assert len(events) == 3
        assert events[0].features["packets"] == 22.0  # 10 fwd + 12 bwd
