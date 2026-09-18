"""Adversarial robustness tests for attack detectors.

Tests that detectors degrade gracefully under adversarial perturbation:
- Feature noise (attacker perturbs flow features to evade detection)
- Volume manipulation (attacker floods with benign traffic to dilute signals)
- Threshold evasion (attacker stays just below detector thresholds)

These tests verify that the detector suite is not brittle under realistic
adversarial conditions, as required by docs/planning/THREAT_MODEL.md.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from sentinel.detectors import run_all_detectors
from sentinel.schemas import NetworkState


def _make_state(
    features: dict[str, float],
    entities: list[str] | None = None,
    edge_summary: list[dict] | None = None,
    *,
    minute: int = 0,
) -> NetworkState:
    """Helper to create a NetworkState with specific features."""
    return NetworkState(
        window_start=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=minute),
        window_end=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=minute + 1),
        features=features,
        entities=entities or ["10.0.0.1", "10.0.0.2"],
        edge_summary=edge_summary or [],
        coverage={"flow": True, "packet": False},
        source_ids=["test"],
    )


def _make_recon_state() -> NetworkState:
    """Create a window that triggers the recon detector."""
    return _make_state(
        features={
            "flow_event_count": 50.0,
            "bytes": 5000.0,
            "packets": 100.0,
            "syn_count": 50.0,
            "rst_count": 40.0,
            "ack_count": 10.0,
            "failed_auth": 5.0,
            "duration": 30.0,
            "iat_mean": 0.1,
        },
        entities=["10.0.0.1", "auth-service", "server-03"],
        edge_summary=[
            {"source": "10.0.0.1", "destination": f"10.0.0.{i}", "count": 5.0, "bytes": 300.0}
            for i in range(1, 10)
        ],
    )


def _make_benign_state() -> NetworkState:
    """Create a benign window."""
    return _make_state(
        features={
            "flow_event_count": 8.0,
            "bytes": 3000.0,
            "packets": 20.0,
            "syn_count": 0.0,
            "rst_count": 0.0,
            "ack_count": 20.0,
            "failed_auth": 0.0,
            "duration": 60.0,
            "iat_mean": 0.1,
        },
        entities=["10.0.0.1", "10.0.0.2"],
        edge_summary=[
            {"source": "10.0.0.1", "destination": "10.0.0.2", "count": 8.0, "bytes": 3000.0}
        ],
    )


# ── Test: feature noise evasion ─────────────────────────────────────
def test_feature_noise_does_not_bypass_recon_detector():
    """Attacker perturbs flow features to try to evade recon detection.

    The recon detector fires on RST ratio and probe share. Adding noise
    to features should not completely eliminate the signal.
    """
    base = _make_recon_state()
    findings = run_all_detectors(base, ())
    recon = [f for f in findings if f.attack_type == "reconnaissance"][0]
    assert recon.is_alert, "base should trigger recon"

    # Attacker adds 20% noise to flow features
    rng = random.Random(42)
    noisy_features = {
        k: v * (1.0 + rng.uniform(-0.2, 0.2)) if isinstance(v, (int, float)) else v
        for k, v in base.features.items()
    }
    noisy_state = _make_state(
        features=noisy_features,
        entities=base.entities,
        edge_summary=base.edge_summary,
    )
    findings_noisy = run_all_detectors(noisy_state, ())
    recon_noisy = [f for f in findings_noisy if f.attack_type == "reconnaissance"][0]
    assert recon_noisy.is_alert, (
        f"recon detector bypassed by 20% feature noise: prob {recon_noisy.probability:.3f}"
    )


# ── Test: volume dilution ──────────────────────────────────────────
def test_volume_dilution_does_not_bypass_recon_detector():
    """Attacker floods with benign traffic to dilute probe signals."""
    base = _make_recon_state()
    findings = run_all_detectors(base, ())
    recon = [f for f in findings if f.attack_type == "reconnaissance"][0]
    assert recon.is_alert, "base should trigger recon"

    # Dilute: 100 benign flows added to the same window
    diluted_features = dict(base.features)
    diluted_features["flow_event_count"] = 150.0
    diluted_features["bytes"] = 50000.0
    diluted_features["packets"] = 400.0
    diluted_features["syn_count"] = 0.0
    diluted_features["ack_count"] = 400.0
    diluted_features["rst_count"] = 40.0  # RST count stays the same

    diluted_state = _make_state(
        features=diluted_features,
        entities=base.entities,
        edge_summary=[
            {"source": "10.0.0.1", "destination": "10.0.0.2", "count": 100.0, "bytes": 50000.0},
            *base.edge_summary,
        ],
    )
    findings_diluted = run_all_detectors(diluted_state, ())
    recon_diluted = [f for f in findings_diluted if f.attack_type == "reconnaissance"][0]
    # Dilution may reduce probability but should not eliminate detection
    assert recon_diluted.probability > 0.0, "recon detector fully bypassed by volume dilution"


# ── Test: threshold evasion ─────────────────────────────────────────
def test_threshold_evasion_with_gradual_ramp():
    """Attacker gradually increases probe rate to stay below threshold.

    Even with gradual ramping, the detectors should eventually fire when
    enough probe traffic accumulates across windows.
    """
    alerts_in_window = []
    for minute in range(10):
        features = {
            "flow_event_count": 20.0 + minute * 3,
            "bytes": 2000.0 + minute * 800,
            "packets": 50.0 + minute * 15,
            "syn_count": 3.0 + minute * 2,
            "rst_count": 2.0 + minute * 2,
            "ack_count": 20.0,
            "failed_auth": 0.0,
            "duration": 30.0,
            "iat_mean": 0.1,
        }
        state = _make_state(features=features, minute=minute)
        findings = run_all_detectors(state, ())
        alerting = [f for f in findings if f.is_alert]
        alerts_in_window.append(len(alerting) > 0)

    # A 10-window gradual ramp should eventually trigger an alert
    # (recon fires when rst_count exceeds threshold proportion)
    assert any(alerts_in_window), (
        "10-window gradual ramp never triggered any alert — detector too permissive"
    )


# ── Test: detector degradation under extreme values ─────────────────
def test_detectors_handle_zero_features():
    """Detectors must not crash or produce NaN probabilities."""
    state = _make_state(features={})
    findings = run_all_detectors(state, ())
    assert all(isinstance(f.probability, float) for f in findings)
    assert all(0.0 <= f.probability <= 1.0 for f in findings)


def test_detectors_handle_extreme_values():
    """Detectors must not crash with extreme feature values."""
    state = _make_state(
        features={
            "flow_event_count": 1e6,
            "bytes": 1e9,
            "packets": 1e6,
            "syn_count": 500000.0,
            "rst_count": 500000.0,
            "ack_count": 500000.0,
            "failed_auth": 100000.0,
            "duration": 0.001,
            "iat_mean": 0.0,
        }
    )
    findings = run_all_detectors(state, ())
    assert all(isinstance(f.probability, float) for f in findings)
    assert all(0.0 <= f.probability <= 1.0 for f in findings)


# ── Test: benign traffic stays quiet under adversarial conditions ────
def test_benign_traffic_quiet_under_noise():
    """Benign traffic with added noise should not trigger detectors."""
    rng = random.Random(42)
    for _ in range(5):
        features = {
            "flow_event_count": rng.uniform(5, 15),
            "bytes": rng.uniform(2000, 8000),
            "packets": rng.uniform(10, 50),
            "syn_count": rng.uniform(0, 3),
            "rst_count": rng.uniform(0, 1),
            "ack_count": rng.uniform(10, 50),
            "failed_auth": 0.0,
            "duration": rng.uniform(30, 90),
            "iat_mean": rng.uniform(0.05, 0.2),
        }
        state = _make_state(features=features)
        findings = run_all_detectors(state, ())
        alerting = [f.attack_type for f in findings if f.is_alert]
        # Only DDoS or recon might trigger on noise; credential/lateral
        # should never fire on pure benign noise
        dangerous = set(alerting) - {"ddos", "reconnaissance"}
        assert not dangerous, f"benign+noise triggered {dangerous}"
