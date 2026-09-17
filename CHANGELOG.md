# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-09-17

### Added
- Core pipeline: ingestion → state building → features → baseline → temporal → rollout → forecast
- 9 attack-type detectors with measured thresholds
- MITRE ATT&CK mapping and Navigator export
- Explainability: SHAP, attention, counterfactuals
- Graph neural network (hand-rolled GAT, no PyG)
- RSSM world model with prior/posterior/decoder
- FastAPI REST API with API-key auth and RBAC
- Streamlit dashboard with live detection
- Walk-forward replay evaluation
- Threshold calibration (leakage-safe)
- CIC-IDS2017 adapter
- Threat-intel enrichment (URLhaus)
- Hash-chain audit ledger
- Compliance mapping (NIST/ISO/SOC2)
- Docker Compose with Prometheus + Grafana
- Next.js 15 frontend scaffold with SENTINEL design tokens
- CI workflow (ruff + pytest)
- SECURITY.md with disclosure policy
