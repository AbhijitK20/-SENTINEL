# SPDX-License-Identifier: Apache-2.0
"""Run a forecast on a telemetry **file** — the problem statement's demo path.

Every surface (CLI, dashboard, API) calls :func:`forecast_from_file` rather than
re-implementing the route from a file to a ``Forecast``, so "what the demo shows"
and "what the API returns" cannot drift apart.

Two forecasters are available and the choice is explicit:

* ``per_horizon`` — the shipped temporal nowcast (``sentinel.predict.forecast``).
* ``imagination`` — the RSSM world model rolled open-loop from the prior
  (``sentinel.world_model.imagine.imagination_forecast``). Needs
  ``world_model_dir``; the world-model version string is recorded in the
  forecast so the two can never be confused downstream.

Coverage is reported, never assumed: a flow CSV produces flow-level features
only, and the returned warnings say so rather than silently scoring a model that
never saw packet-level inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel.ingestion import read_flow_csv
from sentinel.predict import (
    DECISION_THRESHOLD,
    LoadedArtifacts,
    forecast,
)
from sentinel.schemas import Forecast, NetworkState, UnifiedEvent
from sentinel.state_builder import build_network_states
from sentinel.world_model.imagine import imagination_forecast
from sentinel.world_model.train import WorldModelResult, load_world_model

FILE_FORECAST_VERSION = "file-forecast-v1"
PCAP_SUFFIXES = frozenset({".pcap", ".pcapng", ".cap"})
CSV_SUFFIXES = frozenset({".csv"})
Forecaster = Literal["per_horizon", "imagination"]

# Per-event keys that only a packet-level source supplies. Coverage is decided
# from the input events, not from window features: the state builder writes
# explicit 0.0 placeholders for absent packet attributes, so a name check on the
# window would always claim coverage.
PACKET_INPUT_KEYS = frozenset(
    {"ttl", "tcp_window_size", "fragment_flags", "ip_flags", "frag_offset", "retransmission"}
)


class TelemetrySummary(BaseModel):
    """What was read, and what the model could therefore see."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    source_format: Literal["csv", "pcap", "other"]
    events: int = Field(ge=0)
    states: int = Field(ge=0)
    first_window_start: str
    last_window_end: str
    flow_coverage: bool
    packet_coverage: bool
    features_present: int = Field(ge=0)
    ingestion_warnings: list[str] = Field(default_factory=list)


class FileForecast(BaseModel):
    """A forecast plus the provenance of the file that produced it."""

    model_config = ConfigDict(extra="forbid")

    file_forecast_version: str = FILE_FORECAST_VERSION
    forecaster: Forecaster
    telemetry: TelemetrySummary
    forecast: Forecast
    threshold: float
    flagged_windows: list[int] = Field(default_factory=list)


@dataclass(frozen=True)
class LoadedStates:
    """Windowed states read from a file, with the events kept for inspection."""

    states: tuple[NetworkState, ...]
    events: tuple[UnifiedEvent, ...]
    source_format: str
    warnings: tuple[str, ...]


def read_telemetry_file(
    path: str | Path,
    *,
    window_seconds: int = 60,
    stride_seconds: int = 30,
    include_empty: bool = False,
) -> LoadedStates:
    """Read a PCAP or flow CSV and window it into network states.

    The format is chosen by file suffix, which is the only signal available for
    an uploaded file. An unknown suffix is an error, not a guess.
    """
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"Telemetry file does not exist: {source}")
    suffix = source.suffix.lower()
    if suffix in PCAP_SUFFIXES:
        return _from_pcap(source, window_seconds, stride_seconds, include_empty)
    if suffix in CSV_SUFFIXES:
        return _from_csv(source, window_seconds, stride_seconds, include_empty)
    supported = ", ".join(sorted(PCAP_SUFFIXES | CSV_SUFFIXES))
    raise ValueError(f"Unsupported telemetry file '{source.name}': expected one of {supported}")


def _from_pcap(
    source: Path, window_seconds: int, stride_seconds: int, include_empty: bool
) -> LoadedStates:
    from sentinel.pcap_ingestion import read_pcap

    result = read_pcap(source)
    return LoadedStates(
        states=build_network_states(
            result.events,
            window_seconds=window_seconds,
            stride_seconds=stride_seconds,
            include_empty=include_empty,
        ),
        events=result.events,
        source_format="pcap",
        warnings=result.coverage.warnings,
    )


def _from_csv(
    source: Path, window_seconds: int, stride_seconds: int, include_empty: bool
) -> LoadedStates:
    result = read_flow_csv(source)
    warnings = [
        f"Optional column absent from the CSV: {feature}"
        for feature in result.coverage.missing_optional_features
    ]
    return LoadedStates(
        states=build_network_states(
            result.events,
            window_seconds=window_seconds,
            stride_seconds=stride_seconds,
            include_empty=include_empty,
        ),
        events=result.events,
        source_format="csv",
        warnings=tuple(warnings),
    )


def forecast_from_file(
    path: str | Path,
    artifacts: LoadedArtifacts,
    *,
    forecaster: Forecaster = "per_horizon",
    world_model_dir: str | Path | None = None,
    max_horizon: int = 5,
    threshold: float | None = None,
    window_seconds: int = 60,
    stride_seconds: int = 30,
    history_windows: int | None = None,
    imagination_samples: int = 64,
    seed: int = 0,
) -> FileForecast:
    """Forecast the next ``max_horizon`` windows of a telemetry file.

    ``history_windows`` truncates the observed history handed to the world model;
    it should match the ``sequence_length`` the model was trained with, otherwise
    the imagination is conditioned on a sequence length it never saw.
    """
    if forecaster not in ("per_horizon", "imagination"):
        raise ValueError(f"forecaster must be 'per_horizon' or 'imagination', got {forecaster!r}")
    if forecaster == "imagination" and world_model_dir is None:
        raise ValueError("forecaster='imagination' requires world_model_dir")

    resolved_threshold = threshold or artifacts.calibrated_threshold or DECISION_THRESHOLD
    if not 0 < resolved_threshold < 1:
        raise ValueError("threshold must be strictly between zero and one")

    loaded = read_telemetry_file(path, window_seconds=window_seconds, stride_seconds=stride_seconds)
    if not loaded.states:
        raise ValueError(f"No windows could be built from {Path(path).name}")

    schema = artifacts.baseline_result.feature_schema
    ordered = sorted(loaded.states, key=lambda state: state.window_start)
    if forecaster == "imagination":
        core, result = _load_world(world_model_dir)
        history = history_windows or result.sequence_length
        if len(ordered) < history:
            raise ValueError(
                f"file yields {len(ordered)} windows; the world model needs {history} "
                "observed windows before it can imagine"
            )
        window_states = ordered[-history:]
        forecast_out, diagnostics = imagination_forecast(
            window_states,
            core,
            schema,
            result.stage_vocabulary,
            max_horizon=max_horizon,
            threshold=resolved_threshold,
            n_samples=imagination_samples,
            seed=seed,
        )
        extra_warnings = [
            f"Imagination diagnostics: crossing_rate={diagnostics['crossing_rate']:.3f} "
            f"risk_spread={diagnostics['risk_spread']:.3f} "
            f"latent_spread={diagnostics['latent_spread']:.3f}"
        ]
    else:
        window_states = ordered
        forecast_out = forecast(
            window_states, artifacts, max_horizon=max_horizon, threshold=resolved_threshold
        )
        extra_warnings = []

    telemetry = _summarize(path, loaded, ordered, schema.names)
    warnings = list(extra_warnings)
    if not telemetry.packet_coverage:
        warnings.append(
            "No packet-level events in this input: TTL, TCP window, fragmentation, and "
            "retransmission features are absent, so packet-derived signals did not "
            "contribute to this forecast."
        )

    return FileForecast(
        forecaster=forecaster,
        telemetry=telemetry,
        forecast=forecast_out.model_copy(update={"warnings": forecast_out.warnings + warnings}),
        threshold=resolved_threshold,
        flagged_windows=[
            point.window
            for point in forecast_out.probability_timeline
            if point.infiltration_probability >= resolved_threshold
        ],
    )


def _load_world(world_model_dir: str | Path) -> tuple[object, WorldModelResult]:

    root = Path(world_model_dir)
    result_path = root / "world_model.json"
    if not result_path.is_file():
        raise FileNotFoundError(f"World model result not found: {result_path}")
    result = WorldModelResult.model_validate_json(result_path.read_text(encoding="utf-8"))
    return load_world_model(result, root), result


def _packet_input_present(loaded: LoadedStates) -> bool:
    """True when the file actually carried packet-level evidence.

    Decided from the events rather than the windows, because the state builder
    emits explicit 0.0 for absent packet attributes — a window feature name is
    therefore not evidence of anything.
    """
    return any(
        event.event_type == "packet" or PACKET_INPUT_KEYS & set(event.features)
        for event in loaded.events
    )


def _summarize(
    path: str | Path,
    loaded: LoadedStates,
    ordered: list[NetworkState],
    feature_names: list[str],
) -> TelemetrySummary:
    first = ordered[0]
    last = ordered[-1]
    known = set(feature_names)
    present = {name for state in ordered for name in state.features if name in known}
    return TelemetrySummary(
        path=str(path),
        source_format=loaded.source_format if loaded.source_format in ("csv", "pcap") else "other",
        events=len(loaded.events),
        states=len(ordered),
        first_window_start=first.window_start.isoformat(),
        last_window_end=last.window_end.isoformat(),
        flow_coverage=any(state.coverage.get("flow", False) for state in ordered),
        packet_coverage=_packet_input_present(loaded),
        features_present=len(present),
        ingestion_warnings=list(loaded.warnings),
    )


__all__ = [
    "CSV_SUFFIXES",
    "FILE_FORECAST_VERSION",
    "PCAP_SUFFIXES",
    "FileForecast",
    "LoadedStates",
    "TelemetrySummary",
    "forecast_from_file",
    "read_telemetry_file",
]
