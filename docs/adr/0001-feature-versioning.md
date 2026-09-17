# ADR-0001: Feature Versioning Policy

## Status

Accepted

## Context

Features evolve across sprints. Raw identifiers (source_port, destination_port) were replaced with derived behavioural features (port entropy, sequential score, flag ratios). Models trained on different feature versions produce incompatible predictions.

## Decision

- Every feature set has a version string (`FEATURE_VERSION`).
- The version is embedded in `NetworkState.feature_version` and persisted in the model artifact.
- Old feature names are preserved as `LEGACY_ALIASES` with deprecation warnings.
- Models are never retrained on a different feature version without bumping the version string.
- The calibration threshold is version-specific.

## Consequences

- Models are always reproducible: feature_version + config + seed = identical model.
- The UI and API can detect version mismatches and warn.
- Legacy aliases allow gradual migration without breaking existing dashboards.
- Retraining on a new feature version requires re-calibration.
