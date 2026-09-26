"""The problem statement's demo path: a PCAP or CSV file in, a forecast out.

There was no route from a telemetry *file* to a ``Forecast`` before this — the
CLI only scored synthetic scenarios. These tests pin the routing, the coverage
reporting, and the two failure modes an uploaded file actually hits.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.baseline import save_baseline_artifacts, train_baseline
from sentinel.config import BaselineConfig
from sentinel.file_forecast import (
    FILE_FORECAST_VERSION,
    FileForecast,
    forecast_from_file,
    read_telemetry_file,
)
from sentinel.predict import load_artifacts
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest
from sentinel.world_model.train import (
    WorldModelConfig,
    save_world_model_artifacts,
    train_world_model,
)

SCENARIOS = [f"ff{i}" for i in range(6)]
SEQUENCE_LENGTH = 4


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory):
    root = tmp_path_factory.mktemp("file-forecast")
    labelled = generate_labelled_states(SCENARIOS, seed=3, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=3)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=0.5),
        seed=3,
    )
    baseline_dir = root / "baseline"
    save_baseline_artifacts(run, baseline_dir)

    world = train_world_model(
        labelled,
        manifest,
        feature_schema=run.result.feature_schema,
        config=WorldModelConfig(
            hidden_size=8, latent_dim=2, max_epochs=2, kl_anneal_epochs=1, batch_size=64
        ),
        seed=3,
        sequence_length=SEQUENCE_LENGTH,
    )
    world_dir = root / "world"
    save_world_model_artifacts(world, world_dir)
    return load_artifacts(baseline_dir), world_dir


@pytest.fixture
def flow_csv(tmp_path: Path) -> Path:
    path = tmp_path / "flows.csv"
    lines = [
        "timestamp,source_entity,destination_entity,source_port,destination_port,protocol,bytes,packets,duration,tcp_flags,syn_count,ack_count,iat_mean,bidirectional_ratio"
    ]
    start = datetime(2026, 3, 1, tzinfo=UTC)
    for index in range(12):
        stamp = (start + timedelta(seconds=30 * index)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(
            f"{stamp},host-{index % 3},server-a,{41000 + index},443,TCP,"
            f"{1200 + index * 40},12,1.2,SYN ACK,1,11,0.10,0.80"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def packet_pcap(tmp_path: Path) -> Path:
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    path = tmp_path / "capture.pcap"
    packets = []
    start = datetime(2026, 3, 1, tzinfo=UTC)
    for index in range(24):
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
            / TCP(sport=40000 + index, dport=445, flags="SA", window=8192, seq=index * 100)
            / Raw(b"payload")
        )
        packet.time = (start + timedelta(seconds=20 * index)).timestamp()
        packets.append(packet)
    wrpcap(str(path), packets)
    return path


# ── routing ─────────────────────────────────────────────────────────────


def test_reads_a_flow_csv(artifacts, flow_csv: Path) -> None:
    loaded = read_telemetry_file(flow_csv, window_seconds=60, stride_seconds=30)

    assert loaded.source_format == "csv"
    assert loaded.events
    assert loaded.states
    assert all(state.window_end > state.window_start for state in loaded.states)


def test_reads_a_pcap(artifacts, packet_pcap: Path) -> None:
    loaded = read_telemetry_file(packet_pcap, window_seconds=60, stride_seconds=30)

    assert loaded.source_format == "pcap"
    assert all(event.event_type == "packet" for event in loaded.events)
    assert any(state.coverage.get("packet") for state in loaded.states)


def test_rejects_unknown_suffixes(tmp_path: Path) -> None:
    path = tmp_path / "capture.txt"
    path.write_text("not telemetry", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported telemetry file"):
        read_telemetry_file(path)


def test_rejects_missing_files(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="does not exist"):
        read_telemetry_file(tmp_path / "absent.pcap")


# ── forecasting from a file ─────────────────────────────────────────────


def test_per_horizon_forecast_from_csv(artifacts, flow_csv: Path) -> None:
    loaded, _world_dir = artifacts

    result = forecast_from_file(
        flow_csv, loaded, forecaster="per_horizon", max_horizon=3, threshold=0.5
    )

    assert isinstance(result, FileForecast)
    assert result.file_forecast_version == FILE_FORECAST_VERSION
    assert result.forecaster == "per_horizon"
    assert result.telemetry.source_format == "csv"
    assert result.telemetry.flow_coverage is True
    assert len(result.forecast.probability_timeline) == 3
    assert all(
        0.0 <= p.infiltration_probability <= 1.0 for p in result.forecast.probability_timeline
    )
    assert result.threshold == 0.5


def test_imagination_forecast_from_pcap(artifacts, packet_pcap: Path) -> None:
    loaded, world_dir = artifacts

    result = forecast_from_file(
        packet_pcap,
        loaded,
        forecaster="imagination",
        world_model_dir=world_dir,
        max_horizon=2,
        history_windows=SEQUENCE_LENGTH,
        imagination_samples=4,
    )

    assert result.forecaster == "imagination"
    assert "rssm-imagination" in result.forecast.model_version
    assert result.telemetry.packet_coverage is True
    assert any("open-loop imagination" in w for w in result.forecast.warnings)


def test_flagged_windows_follow_the_threshold(artifacts, flow_csv: Path) -> None:
    loaded, _world_dir = artifacts

    strict = forecast_from_file(flow_csv, loaded, max_horizon=3, threshold=0.99)
    loose = forecast_from_file(flow_csv, loaded, max_horizon=3, threshold=0.01)

    assert strict.flagged_windows == []
    assert set(strict.flagged_windows) <= set(loose.flagged_windows)
    assert loose.flagged_windows
    for point in loose.forecast.probability_timeline:
        if point.window in loose.flagged_windows:
            assert point.infiltration_probability >= loose.threshold


def test_csv_forecast_says_packet_signals_were_absent(artifacts, flow_csv: Path) -> None:
    """A flow CSV with no packet columns cannot produce packet features, and the
    forecast must say so instead of quietly scoring a model blind to them."""
    loaded, _world_dir = artifacts

    result = forecast_from_file(flow_csv, loaded, max_horizon=2)

    assert result.telemetry.packet_coverage is False
    assert any("No packet-level events" in w for w in result.forecast.warnings)


def test_csv_with_packet_columns_reports_packet_coverage(artifacts, tmp_path: Path) -> None:
    """A flow CSV may carry header evidence; coverage follows the features."""
    loaded, _world_dir = artifacts
    path = tmp_path / "flows_with_packets.csv"
    lines = [
        "timestamp,source_entity,destination_entity,source_port,destination_port,protocol,"
        "bytes,packets,duration,tcp_flags,syn_count,ack_count,iat_mean,"
        "bidirectional_ratio,ttl,tcp_window_size,fragment_flags,retransmission"
    ]
    start = datetime(2026, 3, 1, tzinfo=UTC)
    for index in range(12):
        stamp = (start + timedelta(seconds=30 * index)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(
            f"{stamp},host-{index % 3},server-a,{41000 + index},443,TCP,1200,12,1.2,"
            f"SYN ACK,1,11,0.10,0.80,{48 + index % 16},1024,16384,{index % 2}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = forecast_from_file(path, loaded, max_horizon=2)

    assert result.telemetry.packet_coverage is True
    assert not any("No packet-level events" in w for w in result.forecast.warnings)
    assert result.telemetry.features_present > 74


def test_imagination_requires_a_world_model(artifacts, flow_csv: Path) -> None:
    loaded, _world_dir = artifacts

    with pytest.raises(ValueError, match="requires world_model_dir"):
        forecast_from_file(flow_csv, loaded, forecaster="imagination")


def test_imagination_reports_missing_artifacts(
    artifacts, packet_pcap: Path, tmp_path: Path
) -> None:
    loaded, _world_dir = artifacts

    with pytest.raises(FileNotFoundError, match="World model result not found"):
        forecast_from_file(
            packet_pcap,
            loaded,
            forecaster="imagination",
            world_model_dir=tmp_path / "nowhere",
            history_windows=SEQUENCE_LENGTH,
        )


def test_imagination_reports_too_little_history(artifacts, flow_csv: Path) -> None:
    loaded, world_dir = artifacts

    with pytest.raises(ValueError, match="the world model needs"):
        forecast_from_file(
            flow_csv,
            loaded,
            forecaster="imagination",
            world_model_dir=world_dir,
            history_windows=200,
        )


def test_rejects_unknown_forecaster(artifacts, flow_csv: Path) -> None:
    loaded, _world_dir = artifacts

    with pytest.raises(ValueError, match="forecaster must be"):
        forecast_from_file(flow_csv, loaded, forecaster="crystal_ball")  # type: ignore[arg-type]


def test_rejects_impossible_thresholds(artifacts, flow_csv: Path) -> None:
    loaded, _world_dir = artifacts

    with pytest.raises(ValueError, match="strictly between zero and one"):
        forecast_from_file(flow_csv, loaded, threshold=1.5)
