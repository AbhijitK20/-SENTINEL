from pathlib import Path

import pytest

from trajectory.ingestion import read_flow_csv

FIXTURE = Path("data/fixtures/flow_sample.csv")


def test_flow_csv_becomes_unified_events() -> None:
    result = read_flow_csv(FIXTURE)

    assert len(result.events) == 2
    assert result.events[0].event_type == "flow"
    assert result.events[0].features["protocol"] == 6
    assert result.events[0].features["tcp_flags"] == 18
    assert result.coverage.packet_features_available is False
    assert "iat_variance" in result.coverage.missing_optional_features


def test_missing_required_column_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "invalid.csv"
    path.write_text("timestamp,source_entity\n2026-01-01T00:00:00Z,a\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required columns"):
        read_flow_csv(path)


def test_invalid_numeric_value_is_rejected(tmp_path: Path) -> None:
    content = FIXTURE.read_text(encoding="utf-8").replace(",1200,", ",not-a-number,", 1)
    path = tmp_path / "invalid-number.csv"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid numeric values in 'bytes'"):
        read_flow_csv(path)
