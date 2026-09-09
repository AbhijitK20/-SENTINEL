from datetime import UTC, datetime

from trajectory.schemas import Forecast, NetworkState, UnifiedEvent


def test_event_and_state_contracts_accept_minimal_valid_data() -> None:
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    event = UnifiedEvent(
        event_id="event-1",
        timestamp=timestamp,
        source_entity="host-a",
        destination_entity="host-b",
        event_type="flow",
        source_format="csv",
        provenance="fixture.csv:1",
    )
    state = NetworkState(
        window_start=timestamp,
        window_end=timestamp,
        source_ids=[event.event_id],
        coverage={"flow": True, "packet": False},
    )
    forecast = Forecast(
        input_window_start=timestamp,
        input_window_end=timestamp,
        horizon_windows=1,
        model_version="test",
        probability_timeline=[{"window": 1, "infiltration_probability": 0.5, "confidence": 0.5}],
        predicted_stage={"name": "Unknown", "probability": 0.5, "confidence": "unknown"},
    )

    assert event.event_id in state.source_ids
    assert forecast.probability_timeline[0].window == 1
