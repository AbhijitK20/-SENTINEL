# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version
numbers are semantic; version *strings* inside the code are separate and
load-bearing, and are registered in `AGENTS.md`.

## [0.2.0] - 2026-09-29

The submission-hardening pass. No model architecture changed.

### Fixed

- **Missing telemetry was encoded as a measurement of zero, then standardized.**
  `vectorize_states` filled an absent feature with `0.0` in raw space and
  z-scored it, landing at `(0 - mean) / scale` — up to **z = -104.47** against
  the committed bundle, and reachable on any flow-only capture. Imputation now
  happens in z-space at the training mean. `state-features-v1` -> `v2`.
- **`detect_credential` and `detect_malware` multiplied a count by a count.**
  Two failed authentications reported `26.0` per minute and saturated at
  `probability = 1.0`. The band is a rate; the window is already the time unit.
- **The exfiltration stage was unreachable.** `external_destination_count`
  matched a literal prefix and one hard-coded address, so it was identically
  `0.0` on every window of the corpus. It now decides by address.
- **The sequence detector normalised on its own maximum**, pinning its argmax at
  1.0 so `min_probability` was unreachable and `is_alert` was constant `True`.
  A second defect divided by a weight counted once per successor. Both fixed,
  and the component is documented as the intra-window heuristic it is.
- **`fit_transition_model` rejected legitimate windows.** Absent packet evidence
  is now an absent key rather than a zero, so two windows can differ in key set;
  the function accepts the fitted schema's `feature_names`.
- **The published demo key was silently accepted as an administrative
  credential.** Demo mode is now explicit; with `SENTINEL_DEMO_MODE=false` the
  app refuses to start without a real key and rejects the published one.
- **The dashboard's attack-runner button** was gated only on "not Streamlit
  Cloud", which passes inside this repository's own image. It now also requires
  a loopback bind.
- **The panel container stack was a module-level list**, shared across browser
  sessions. It now lives in session state.

### Changed

- **Synthetic generator `synthetic-recon-lateral-v2` -> `v3`.** The old corpus
  was trivially separable (single-feature ROC-AUC 0.9833 vs a full model's
  0.9933). Benign traffic is now a mixture whose volume overlaps the attack
  phases, destinations and ports come from shared pools, and phase lengths vary
  per scenario. The gap between one feature and the full set is now 0.113
  instead of 0.0072.
- Release bundle regenerated on v3. **Headline numbers are lower** and the
  detector bands were re-swept: `KNOWN_EDGE_BYTES_PER_SEC` 750/900 ->
  1500/1800 B/s.
- The `idurar-erp-crm` sibling-repository dependency moved out of
  `docker-compose.yml` into an opt-in `docker-compose.lab.yml`.
- `docs/CLAIMS.md` now covers README, RESULTS, ABSTRACT, the presentation
  outline and the generators that build the submitted artifacts.

### Removed

- `web/` — an unbuildable Next.js prototype referenced by nothing, with a
  drifted palette. Recorded in `docs/DESIGN.md`.
- The stale deck PDF, which was generated from the previous seven-slide deck and
  could not be regenerated here. See `deliverables/README.md`.

## [0.1.0] - 2026-09-17

First complete pipeline. See git history for the sprint-by-sprint build.

[0.2.0]: https://github.com/AbhijitK20/-SENTINEL/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AbhijitK20/-SENTINEL/releases/tag/v0.1.0
