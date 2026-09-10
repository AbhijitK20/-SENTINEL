"""Live detection engine: bounded-window inference over streaming telemetry.

The engine turns a stream of :class:`UnifiedEvent` into rolling windows of
``stride_seconds`` (event-time based, so replayed captures, file-tailed
sensors, and real interfaces behave identically), scores each window with the
real trained artifacts via :func:`trajectory.predict.forecast`, and keeps a
bounded history for the dashboard.

Event sources
-------------

- :class:`CsvReplaySource` — replays a flow CSV at a configurable speed
  (simulated seconds per real second), using the strict CICFlowMeter loader.
- :class:`JsonlSensorSource` — tails a JSONL file written by a sensor or the
  scripted attack demo; each line is one event with its features.
- :class:`ScapyInterfaceSource` — optional; sniffs a live interface into
  packet events (requires the ``pcap`` extra with scapy installed).

Nothing here fabricates probabilities: windows with no events produce no
state, and every emitted window carries the same warnings the offline
forecast would produce.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, Field

from trajectory.cic_ids2017 import load_flow_csv
from trajectory.predict import DECISION_THRESHOLD, forecast
from trajectory.schemas import (
    DrivingFeature,
    Forecast,
    NetworkState,
    StageEvidence,
    UnifiedEvent,
)
from trajectory.state_builder import build_network_states

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from trajectory.predict import LoadedArtifacts

LIVE_ENGINE_VERSION = "live-engine-v1"

# Memory bound: at most this many raw events are buffered. The engine only
# needs the most recent window plus history states, so dropping the oldest
# events under pressure is safe and explicit.
MAX_BUFFERED_EVENTS = 50_000


class LiveWindow(BaseModel):
    """One emitted window with its forecast, for the dashboard."""

    model_config = ConfigDict(extra="forbid")

    window_start: datetime
    window_end: datetime
    event_count: int
    entities: int
    probability: float
    threshold: float
    stage: str
    stage_confidence: str
    mitre_reference: str | None
    stage_evidence: list[StageEvidence] = Field(default_factory=list)
    driving_features: list[DrivingFeature] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class LiveStatus(BaseModel):
    """Thread-safe snapshot of engine state for the UI."""

    model_config = ConfigDict(extra="forbid")

    engine_version: str = LIVE_ENGINE_VERSION
    source: str
    running: bool
    events_seen: int
    windows_emitted: int
    threshold: float
    model_version: str
    history: list[LiveWindow] = Field(default_factory=list)
    last_error: str | None = None


class EventSource(Protocol):
    """A source pushes events into the engine queue until stopped."""

    name: str

    def run(self, events: queue.Queue[UnifiedEvent], stop: threading.Event) -> None: ...


class _SourceBase:
    """Shared worker-thread plumbing for sources."""

    name = "source"

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None

    def start_in(self, events: queue.Queue[UnifiedEvent], stop: threading.Event) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError(f"source {self.name!r} is already running")
        self._thread = threading.Thread(
            target=self.run, args=(events, stop), name=f"live-source-{self.name}", daemon=True
        )
        self._thread.start()


class CsvReplaySource(_SourceBase):
    """Replay a flow CSV in event-time order at ``speed`` x real time.

    ``speed`` is simulated seconds per real second: 60 plays one hour of
    capture in one minute. The file is loaded once with the strict loader
    (unmapped labels abort); pass ``time_window`` to bound large captures.
    """

    name = "csv-replay"

    def __init__(
        self,
        path: str | Path,
        *,
        speed: float = 60.0,
        scenario_id: str | None = None,
        time_window: tuple[datetime, datetime] | None = None,
    ) -> None:
        super().__init__()
        if speed <= 0:
            raise ValueError("speed must be positive")
        self._path = Path(path)
        self._speed = speed
        self._scenario_id = scenario_id or self._path.stem
        self._time_window = time_window

    def run(self, events: queue.Queue[UnifiedEvent], stop: threading.Event) -> None:
        loaded = load_flow_csv(
            self._path, scenario_id=self._scenario_id, time_window=self._time_window
        )
        loaded.sort(key=lambda event: event.timestamp)
        previous_ts: datetime | None = None
        for event in loaded:
            if stop.is_set():
                return
            if previous_ts is not None and self._speed < 1e12:
                delay = (event.timestamp - previous_ts).total_seconds() / self._speed
                if delay > 0:
                    time.sleep(min(delay, 5.0))  # cap stalls from capture gaps
            previous_ts = event.timestamp
            events.put(event)
        events.put(_SENTINEL)


class JsonlSensorSource(_SourceBase):
    """Tail a JSONL event file (one event per line) until it stops growing.

    Lines carry at least ``timestamp``, ``src``, ``dst``; numeric feature
    keys pass through into the event. This is the attack-demo wire format:
    the scripted attack appends lines and the engine detects them live.
    """

    name = "jsonl-sensor"

    def __init__(
        self,
        path: str | Path,
        *,
        scenario_id: str = "live-sensor",
        poll_seconds: float = 0.25,
        follow: bool = True,
    ) -> None:
        super().__init__()
        self._path = Path(path)
        self._scenario_id = scenario_id
        self._poll_seconds = poll_seconds
        self._follow = follow

    def run(self, events: queue.Queue[UnifiedEvent], stop: threading.Event) -> None:
        counter = 0
        with self._path.open("r", encoding="utf-8") as handle:
            while not stop.is_set():
                line = handle.readline()
                if line == "":
                    if not self._follow:
                        break
                    time.sleep(self._poll_seconds)
                    continue
                if not line.strip():
                    continue
                record = json.loads(line)
                counter += 1
                features = {key: float(value) for key, value in record.get("features", {}).items()}
                events.put(
                    UnifiedEvent(
                        event_id=f"{self._scenario_id}:live:{counter}",
                        timestamp=_parse_ts(record["timestamp"]),
                        source_entity=str(record["src"]),
                        destination_entity=str(record["dst"]),
                        event_type=record.get("event_type", "flow"),
                        features=features,
                        source_format="replay",
                        provenance=f"live-sensor:{self._scenario_id}",
                    )
                )
        events.put(_SENTINEL)


class EventReplaySource(_SourceBase):
    """Replay already-normalized events without a local file or subprocess.

    This source is suitable for hosted demos because the events live in memory
    and the dashboard only needs to start one short-lived worker thread.
    """

    name = "event-replay"

    def __init__(
        self,
        events: list[UnifiedEvent] | tuple[UnifiedEvent, ...],
        *,
        speed: float = 60.0,
    ):
        super().__init__()
        if speed <= 0:
            raise ValueError("speed must be positive")
        self._events = tuple(sorted(events, key=lambda event: event.timestamp))
        self._speed = speed

    def run(self, events: queue.Queue[UnifiedEvent], stop: threading.Event) -> None:
        previous_ts: datetime | None = None
        for event in self._events:
            if stop.is_set():
                return
            if previous_ts is not None:
                delay = (event.timestamp - previous_ts).total_seconds() / self._speed
                if delay > 0:
                    time.sleep(min(delay, 0.25))
            previous_ts = event.timestamp
            events.put(event)
        events.put(_SENTINEL)


class ScapyInterfaceSource(_SourceBase):
    """Sniff a live interface into packet events (requires scapy).

    Each TCP/UDP packet becomes a packet event with flag and size features
    compatible with the trained schemas. Root privileges are required by the
    OS to capture; no network traffic is generated by this source.
    """

    name = "scapy-interface"

    def __init__(self, interface: str) -> None:
        super().__init__()
        self._interface = interface

    def run(self, events: queue.Queue[UnifiedEvent], stop: threading.Event) -> None:
        try:
            from scapy.all import sniff  # noqa: PLC0415 - optional dependency
        except ImportError:
            events.put(_SourceError("scapy is not installed; use the pcap extra"))
            return

        counter = 0

        def handle_packet(packet) -> None:  # noqa: ANN001 - scapy object
            nonlocal counter
            if stop.is_set():
                return
            event = _packet_to_event(packet, counter)
            if event is not None:
                counter += 1
                events.put(event)

        sniff(
            iface=self._interface or None,
            prn=handle_packet,
            stop_filter=lambda _packet: stop.is_set(),
            store=False,
        )
        events.put(_SENTINEL)


class _SourceError:
    """In-band error marker so source failures reach the UI."""


_SENTINEL = _SourceError()  # reuse the marker type for end-of-stream


class LiveEngine:
    """Rolling-window detection over a live event stream.

    Windows are emitted in event time: once an event crosses the next stride
    boundary, that window is closed and forecast. The first event anchors the
    window grid, exactly like the offline builder, so replayed captures and
    live interfaces behave identically.
    """

    def __init__(
        self,
        artifacts: LoadedArtifacts,
        *,
        source: EventSource,
        window_seconds: int = 60,
        stride_seconds: int = 30,
        history: int = 3,
        threshold: float | None = None,
        max_history: int = 120,
    ) -> None:
        if window_seconds <= 0 or stride_seconds <= 0:
            raise ValueError("window_seconds and stride_seconds must be positive")
        if history < 1:
            raise ValueError("history must be positive")
        if stride_seconds > window_seconds:
            raise ValueError("stride must not exceed the window duration")
        self._artifacts: LoadedArtifacts = artifacts
        self._source = source
        self._window_seconds = window_seconds
        self._stride_seconds = stride_seconds
        self._history_length = history
        self._threshold = threshold  # None -> artifact-calibrated -> 0.5
        self._max_history = max_history

        self._queue: queue.Queue[UnifiedEvent | _SourceError] = queue.Queue()
        self._stop = threading.Event()
        self._buffer: deque[UnifiedEvent] = deque(maxlen=MAX_BUFFERED_EVENTS)
        self._states: list[NetworkState] = []
        self._history: deque[LiveWindow] = deque(maxlen=max_history)
        self._lock = threading.Lock()
        self._anchor: datetime | None = None
        self._next_boundary: datetime | None = None
        self._events_seen = 0
        self._last_forecast: Forecast | None = None
        self._last_error: str | None = None
        self._worker: threading.Thread | None = None

    # ── lifecycle ────────────────────────────────────────────────────
    def start(self) -> None:
        """Start the configured source; the engine processes on ``poll()``."""
        if self._worker is not None and self._worker.is_alive():
            raise RuntimeError("live engine already started")
        self._stop.clear()
        self._source.start_in(self._queue, self._stop)  # type: ignore[attr-defined]
        self._worker = threading.current_thread()

    def stop(self) -> None:
        self._stop.set()

    @property
    def source_name(self) -> str:
        return self._source.name

    @property
    def effective_threshold(self) -> float:
        return (
            self._threshold
            if self._threshold is not None
            else (
                self._artifacts.calibrated_threshold
                if self._artifacts.calibrated_threshold is not None
                else DECISION_THRESHOLD
            )
        )

    # ── ingestion ────────────────────────────────────────────────────
    def ingest(self, event: UnifiedEvent) -> None:
        """Direct ingestion path (used by tests and embedded integrations)."""
        with self._lock:
            self._accept(event)

    def _accept(self, event: UnifiedEvent) -> None:
        self._buffer.append(event)
        self._events_seen += 1
        if self._anchor is None:
            self._anchor = event.timestamp
            self._next_boundary = self._anchor + timedelta(seconds=self._stride_seconds)
        assert self._next_boundary is not None
        while event.timestamp >= self._next_boundary:
            self._emit_window(
                self._next_boundary - timedelta(seconds=self._stride_seconds), self._next_boundary
            )
            self._next_boundary += timedelta(seconds=self._stride_seconds)

    # ── processing ───────────────────────────────────────────────────
    def poll(self) -> LiveStatus:
        """Drain queued events, emit due windows, return a UI snapshot."""
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, _SourceError):
                if item is _SENTINEL:
                    self._stop.set()
                else:
                    self._last_error = str(item)
                continue
            with self._lock:
                self._accept(item)
        with self._lock:
            return LiveStatus(
                source=self._source.name,
                running=not self._stop.is_set(),
                events_seen=self._events_seen,
                windows_emitted=len(self._history),
                threshold=self.effective_threshold,
                model_version=self._artifacts.baseline_result.model_version,
                history=list(self._history),
                last_error=self._last_error,
            )

    def _emit_window(self, start: datetime, end: datetime) -> None:
        window_events = [event for event in self._buffer if start <= event.timestamp < end]
        if not window_events:
            return  # empty windows are skipped, never fabricated
        (state,) = build_network_states(
            window_events, window_seconds=self._stride_seconds, stride_seconds=self._stride_seconds
        )
        state = state.model_copy(update={"window_start": start, "window_end": end})
        self._states.append(state)
        self._states = self._states[-(self._history_length + 1) :]

        result = forecast(
            self._states,
            self._artifacts,
            max_horizon=1,
            threshold=self.effective_threshold,
        )
        self._last_forecast = result
        probability = result.probability_timeline[-1].infiltration_probability
        stage = result.stage_mapping
        self._history.append(
            LiveWindow(
                window_start=start,
                window_end=end,
                event_count=len(window_events),
                entities=len(state.entities),
                probability=probability,
                threshold=self.effective_threshold,
                stage=stage.stage,
                stage_confidence=stage.confidence,
                mitre_reference=stage.mitre_reference,
                stage_evidence=list(stage.evidence),
                driving_features=list(result.driving_features),
                warnings=list(result.warnings),
            )
        )


def _parse_ts(raw: str | float | int) -> datetime:
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=UTC)
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _packet_to_event(packet, counter: int) -> UnifiedEvent | None:  # noqa: ANN001
    """Convert one scapy packet to a packet event; non-IP packets are dropped."""
    from scapy.layers.inet import IP, TCP, UDP  # noqa: PLC0415 - optional dependency

    if IP not in packet:
        return None
    ip = packet[IP]
    features: dict[str, float] = {"bytes": float(len(packet)), "packets": 1.0}
    if TCP in packet:
        tcp = packet[TCP]
        features.update(
            {
                "destination_port": float(tcp.dport),
                "source_port": float(tcp.sport),
                "syn_count": 1.0 if tcp.flags.S else 0.0,
                "ack_count": 1.0 if tcp.flags.A else 0.0,
                "fin_count": 1.0 if tcp.flags.F else 0.0,
                "rst_count": 1.0 if tcp.flags.R else 0.0,
                "psh_count": 1.0 if tcp.flags.P else 0.0,
                "retransmission": 0.0,
            }
        )
    elif UDP in packet:
        features.update(
            {
                "destination_port": float(packet[UDP].dport),
                "source_port": float(packet[UDP].sport),
            }
        )
    timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)
    return UnifiedEvent(
        event_id=f"live-capture:{counter}",
        timestamp=timestamp,
        source_entity=str(ip.src),
        destination_entity=str(ip.dst),
        event_type="packet",
        features=features,
        source_format="pcap",
        provenance="live-capture",
    )


__all__ = [
    "LIVE_ENGINE_VERSION",
    "CsvReplaySource",
    "EventReplaySource",
    "EventSource",
    "JsonlSensorSource",
    "LiveEngine",
    "LiveStatus",
    "LiveWindow",
    "ScapyInterfaceSource",
]
