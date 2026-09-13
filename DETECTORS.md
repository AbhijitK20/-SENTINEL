# Attack-Type Detector Suite (Phase 1)

Status: implemented and tested (`tests/test_detectors.py`,
`tests/test_telemetry.py`, `tests/test_correlation.py`). These detectors
complement the trained infiltration forecaster; they do not replace it.

## Architecture

```
UnifiedEvent stream → rolling NetworkState windows
        ├── trained forecaster  → P(infiltration), stage mapping (unchanged)
        └── attack-type detectors (run_all_detectors)
                ↓ six AttackFinding contracts per window
        asset-registry risk fusion (trajectory/assets.py)
        ↓
incident correlation (trajectory/correlation.py) → Incident cases
        ↓
dashboard Live tab: risk grid + incident panel + analyst feedback
```

Every detector emits the same `AttackFinding` schema regardless of its
internal logic: `attack_type`, `probability`, `severity`, `confidence`,
`is_alert`, window bounds, `mitre_technique`, `affected_assets`, `evidence`,
`warnings`, and `model_version` (`detectors-v1`).

## Detectors and thresholds

Thresholds were tuned on measured benign/attack distributions from
`synthetic-recon-lateral-v1` (not guessed). Constants live in
`trajectory/detectors.py`.

| Type | MITRE | Signal | Alert rule |
|---|---|---|---|
| DDoS | T1498 | flows/s + bytes/s z-score vs benign history | z ≥ 6 (capped 0.95) |
| Reconnaissance | T1046 | SYN+RST probe share; low-byte edge share (gated by ≥6 edges) | band score ≥ 0.80 |
| Credential abuse | T1110 | failed auths per minute (mean × flows) | ≥ 2.0/min |
| Lateral movement | T1021 | bytes on internal edges unseen in last 5 windows | ≥ 50k bytes |
| Command & Control | T1071 | **insufficient telemetry** — never scores | — |
| Exfiltration | T1048 | bytes z-score vs benign history (divisor 10) | z ≥ 8 |

## Honesty rules

- **No fabricated scores.** C2 requires DNS/TLS metadata that flow telemetry
  does not carry; it returns probability 0.0 with an explicit warning. DDoS
  has no volumetric-flood scenario in the validation data and says so.
- **Cold-start conservatism.** Baseline-dependent signals (z-scores, new-edge
  counts, exfil floor) are disabled or capped sub-alert until ≥3 benign
  history windows exist, with a warning on the finding.
- **Associations, not proof.** Findings describe telemetry patterns; the
  wording everywhere avoids claiming technique confirmation.
- **Recommendations, never auto-response.** Incidents carry analyst-approved
  suggested actions; nothing is executed automatically.

## Incident correlation

Alerting findings whose windows overlap or sit within 300 s chain into one
`Incident` with a stage-ordered progression (Reconnaissance → Credential
Abuse → Lateral Movement → Exfiltration), fused risk
(`0.5*probability + 0.3*asset_criticality + 0.2*severity`, +0.05 per
additional chained type), affected assets from the registry
(`trajectory/assets.py`, default lab topology), and deduplicated
recommendations.

## Analyst feedback

`trajectory/feedback.py` is an append-only JSONL store of incident verdicts
(`true_positive`, `false_positive`, `wrong_attack_type`, `late_alert`,
`insufficient_evidence`, `useful_alert`). There is deliberately **no
retraining path**: production models are never retrained from unreviewed
analyst input. The Live tab records verdicts to `reports/live/feedback.jsonl`
(git-ignored).

## Phase 2 telemetry stubs

`trajectory/telemetry.py` normalizes DNS and auth-log lines into
`UnifiedEvent` records (event types `dns_query`, `auth_event`) with explicit
provenance. They are format-stubs demonstrating the multi-telemetry path, not
validated ingestion for production log dialects.

## Known limitations

- Trained on/validated against synthetic replay only; real-traffic detector
  evaluation is future work (the CIC-trained forecaster benchmarks live in
  `REAL_BENCHMARK.md`).
- DDoS and C2 are honest stubs (see above); no volumetric or beaconing
  scenario exists to validate them against.
- Windows are 30–60 s; DDoS tempo and long-horizon insider behaviour need
  parallel window scales (roadmap item 7).
