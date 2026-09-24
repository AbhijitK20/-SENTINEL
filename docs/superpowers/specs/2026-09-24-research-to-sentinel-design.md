# Research-to-SENTINEL Integration Design

## Goal

Transfer defensible defensive-engineering ideas from all repositories in `research/repos/` into SENTINEL, correcting misleading risk and coverage semantics first, then grounding forecasts and detection content in data and tests.

## Current-State Findings

- `research/repos/` contains 12 ignored reference clones; `.gitignore` already excludes the directory.
- SENTINEL already has CSV and PCAP ingestion, event-time windowing, feature extraction, a trained baseline/GRU inference path, walk-forward evaluation, a sequence detector, a recursive ridge rollout model, URLhaus threat-intelligence ingestion, detector tests, API metrics, and ATT&CK Navigator export endpoints.
- Recent working-tree edits added `threat_enrichment.py`, a tenth entropy finding, `/v1/attack-coverage`, `/v1/attack-coverage/navigator`, `/v1/predict/next`, a changed risk formula, and related tests/auth changes. Preserve and audit these edits; do not replace or silently discard them.
- Current ATT&CK coverage counts a technique whenever a finding exists, even when its probability is zero. It does not mean the required telemetry or detector is available.
- The per-technique EPSS and KEV values in `threat_enrichment.py` are hand-authored technique-level estimates. EPSS and CISA KEV are vulnerability/CVE-oriented sources, so these values must not be presented as authoritative external intelligence.
- `chain_risk_score`, `markov_chain_prob`, `entropy_anomaly_score`, and `should_auto_block` exist but are not integrated in the normal API path. `should_auto_block` is not to be connected to a live enforcement action.
- `sequence_detector.py` already predicts next attack types from a static transition matrix, and `rollout.py` already provides a distinct, train-only, recursively evaluated forecasting path. Avoid a duplicate Markov feature.
- `telemetry.py` explicitly describes DNS/auth adapters as stubs; `pcap_ingestion.py` and `state_builder.py` already provide core network parsing/aggregation. Prefer improving these paths with fixtures over importing another parser stack.

## Research Repository Disposition

| Repository | Transferable defensive idea | Disposition |
|---|---|---|
| `attack-chain-prediction` | Empirical transition counts, constrained candidate generation, geometric chain aggregation, and held-out evaluation | Reuse concepts only after deriving transitions from checked-in, licensed attack-flow/campaign data and comparing with existing sequence detector/rollout. Do not claim the repository's benchmark results for SENTINEL. |
| `soc-home-lab` | Detection-as-code lifecycle, positive/negative tests, Sigma/Suricata rule examples, event timeline | Reuse test lifecycle and only rules expressible from SENTINEL's existing normalized telemetry. Do not import Wazuh/SIEM stack or offensive emulation. |
| `sentinelx` | Normalized multi-source event parsing, stateful time windows, deduplication, cross-source correlation | Reuse applicable parsing/correlation patterns; keep `UnifiedEvent`, `LiveEngine`, `ThreatIntelFeed`, and current replay pipeline as canonical. Avoid duplicate parser/report subsystems. |
| `sentinel-dns` | Per-label Shannon entropy and conservative threat-intel confirmation | Apply to actual DNS query-name features only. Current generic endpoint/byte entropy heuristic is not equivalent and must not be marketed as DNS tunneling detection. |
| `attack-coverage-dashboard` | STIX ATT&CK parsing, data-source inventory, weighted coverage, Navigator export | Correct coverage meaning and provenance; add offline-compatible data-source-aware score/export using an explicit inventory. No runtime network fetch from `src/sentinel`. |
| `sentinel-mavlink` | Learning/baseline phase and rule-level evaluation | Domain-specific MAVLink rules do not transfer. Reuse baseline calibration/evaluation discipline only if compatible with existing leakage guards. |
| `network-attack-simulator` | Simulated network states for attack-planning evaluation | Optional test/evaluation source only. Do not install its DQN stack or add attack planning to SENTINEL runtime. |
| `bettercap` | Passive event/observation concepts | Offensive MITM, spoofing, credential collection, and attack-control functions are out of scope. |
| `eaphammer` | None applicable to current flow-monitoring product | Wireless credential attacks and evil-twin behavior out of scope. |
| `zarp` | None applicable to current flow-monitoring product | Offensive LAN poisoning/sniffing/DoS out of scope. |
| `slipstream` | Network boundary/security research context | NAT/firewall bypass exploit out of scope. |
| `nym` | Privacy properties of network transport | Not an intrusion detector or current product requirement; no integration planned. |

## Architecture and Stages

### Stage A — Evidence-backed risk and coverage semantics

1. Replace the hand-authored EPSS/KEV-by-technique interpretation. Keep behavior/asset-based risk as the supported baseline. Accept EPSS or KEV enrichment only when it is attached to an identifiable CVE and backed by a locally loaded, provenance-bearing feed/record. No API fetch from `src/sentinel`.
2. Make incident risk calculations use one documented formula. Either integrate geometric mean over distinct observed alert findings with an explicit impact input, or remove the unused helper; do not retain two conflicting risk formulas.
3. Define coverage dimensions separately:
   - detector implemented for a technique;
   - telemetry requirements met in the evaluated window/source inventory;
   - alert observed above the detector threshold.
   A zero-probability finding is not evidence of detection coverage.
4. Provide explicit unavailable/unknown values and explain missing telemetry. Keep the existing API compatible where possible; if response fields or Pydantic contracts change, update `docs/DATA_CONTRACTS.md` and bump the relevant version.

### Stage B — Data-grounded attack progression forecasting

1. Parse the already-cloned ATT&CK Flow and campaign sequence data with a deterministic offline script. Record exact source files, source version, license/provenance, normalization decisions, and generated artifact checksum.
2. Estimate transition probabilities from counts with a documented smoothing method and minimum-support metadata. Do not call hand-authored values empirical.
3. Compare the learned next-step model with the existing `sequence_detector.py` and `rollout.py` using scenario-level walk-forward splits. Train/fit only on training scenarios, select thresholds on validation, and touch test data once at the end.
4. Only replace or augment the existing predictor if held-out results improve over the existing baseline and warnings report low-support transitions. An LSTM is not in this stage unless data and measured benefit justify its dependency/runtime cost.

### Stage C — Coverage analytics and Navigator export

1. Use a versioned, checked-in ATT&CK technique/data-source snapshot or an explicit compact subset generated from the cloned STIX bundle; runtime stays offline.
2. Weight technique coverage by actual configured source availability/quality, and disclose missing data sources. Keep detector capability separate from observed alerts.
3. Generate Navigator v4.5 layers from the same canonical coverage function. Include uncovered techniques as disabled or omit them consistently with tests; color/score must match the documented semantics.
4. Expose analytics through authenticated API and existing dashboard surfaces only if the current UI structure supports it without a second dashboard application.

### Stage D — Detection-as-code and ingestion quality

1. Adapt only web/network rules whose fields are present in `UnifiedEvent`/`NetworkState` (e.g. scanning, failed-auth burst, suspicious DNS label length/entropy when actual query names are available).
2. Each rule requires a malicious fixture and a benign counterexample, a stable ATT&CK mapping, explicit required telemetry, and an honest warning when required evidence is absent.
3. Improve auth/DNS log parsing only from documented representative formats and fixture-backed behavior. Preserve existing CSV/PCAP parser contracts and offline-first boundary.
4. Do not import the reference evaluator's `eval()`-based Sigma condition parser. If a true Sigma import is required later, select a maintained dependency explicitly in a separate design.

## API/Versioning

- Risk or detector behavior changes require version bumps for the affected model/rules and preservation or loud rejection of incompatible artifacts.
- Pydantic `extra="forbid"` contracts remain strict. Any public response/schema change updates `docs/DATA_CONTRACTS.md` and version metadata.
- The endpoint names already added (`/v1/attack-coverage`, `/v1/attack-coverage/navigator`, `/v1/predict/next`) should be retained only after their semantics and auth roles are corrected and tested.

## Safety and Scope

- SENTINEL remains a passive/offline-first defensive analytics product. No live automatic IP blocking, active scanning, attack orchestration, wireless attacks, NAT bypass, or credential collection is added to the product runtime.
- Existing bounded local lab scripts remain separately invoked and limited to the Idurar lab target; this design does not expand their payloads or network scope.
- No new third-party dependencies unless the existing standard library and installed dependencies cannot meet an approved requirement.

## Verification

- Unit tests cover provenance/unknown-data behavior, risk monotonicity and bounds, coverage dimensions and missing-source behavior, transition probabilities against held-out examples, and Navigator schema.
- Existing detector tests retain both positive and benign negative controls. Entropy tests use actual DNS-name character labels, not hashed endpoint strings.
- Run the project gate: `uv run ruff check src tests scripts && uv run ruff format --check src tests scripts && uv run pytest -q`.
- Any published accuracy, coverage, or performance number must come from a script run against a licensed dataset during that run; otherwise document it as `PENDING`.

## Acceptance Criteria

1. Risk outputs no longer label arbitrary technique-level constants as live EPSS/KEV evidence.
2. Coverage reports distinguish detector existence, telemetry availability, and actual alert evidence; zero-probability results do not count as observed coverage.
3. A learned transition predictor identifies its input data/version, support counts, evaluation split, and limitations; it is compared against the existing sequence detector and rollout before becoming the default.
4. Navigator export and dashboard/API display use the same coverage calculation.
5. Detection additions have positive and negative tests and state telemetry requirements.
6. Full project gate passes, and relevant versions/contracts/docs are updated.
