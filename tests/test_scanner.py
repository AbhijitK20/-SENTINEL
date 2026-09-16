import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "demo_scanner",
    Path(__file__).resolve().parent.parent / "apps" / "vulnerable" / "scanner.py",
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_parse_syslog_line = _MODULE._parse_syslog_line


def test_login_attempt_survives_redirect_following() -> None:
    event = _parse_syslog_line(
        "2026-09-14T06:00:00+00:00 demo-sentinel http "
        "src=172.27.0.7 dst=127.0.0.1 dport=5000 "
        "method=POST path=/login status=200 auth=failure",
        1,
    )

    assert event is not None
    assert event["features"]["auth_attempt"] == 1.0
    assert event["features"]["failed_auth"] == 1.0
    assert event["destination_entity"] == "127.0.0.1:/login"


def test_non_auth_success_is_not_failed_auth() -> None:
    event = _parse_syslog_line(
        "2026-09-14T06:00:00+00:00 demo-sentinel http "
        "src=172.27.0.7 dst=127.0.0.1 dport=5000 "
        "method=GET path=/dashboard status=200",
        2,
    )

    assert event is not None
    assert event["features"]["auth_attempt"] == 0.0
    assert event["features"]["failed_auth"] == 0.0


def test_successful_login_is_not_failed_auth() -> None:
    event = _parse_syslog_line(
        "2026-09-14T06:00:00+00:00 demo-sentinel http "
        "src=172.27.0.7 dst=127.0.0.1 dport=5000 "
        "method=POST path=/login status=302 auth=success",
        3,
    )

    assert event is not None
    assert event["features"]["auth_attempt"] == 1.0
    assert event["features"]["failed_auth"] == 0.0


def test_auth_features_aggregate_as_counts() -> None:
    from sentinel.state_builder import build_network_states

    events = []
    for index in range(3):
        event = _parse_syslog_line(
            f"2026-09-14T06:00:{index:02d}+00:00 demo-sentinel http "
            "src=172.27.0.7 dst=127.0.0.1 dport=5000 "
            "method=POST path=/login status=200 auth=failure",
            index,
        )
        assert event is not None
        from sentinel.schemas import UnifiedEvent

        events.append(UnifiedEvent.model_validate(event))

    (state,) = build_network_states(events, window_seconds=30, stride_seconds=30)
    assert state.features["flow_event_count"] == 3.0
    assert state.features["auth_attempt"] == 3.0
    assert state.features["failed_auth"] == 3.0
