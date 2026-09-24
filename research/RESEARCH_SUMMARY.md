# Research Repos — Reference Summary

Cloned into `research/repos/` for reference only. Not tracked in git.

## Repos Overview

| Repo | What it does | Closest to SENTINEL because |
|------|-------------|---------------------------|
| attack-chain-prediction | LSTM-Markov attack chain forecasting (SECRYPT 2026) | Same core idea: predict kill chain |
| attack-coverage-dashboard | MITRE ATT&CK coverage analytics (Streamlit) | ATT&CK matrix visualization |
| soc-home-lab | 11-service Dockerized SOC (Wazuh+Suricata+TheHive) | Same stack pattern |
| sentinelx | Multi-source SOC detection platform | Multi-attack-type detection |
| sentinel-mavlink | MAVLink drone IDS (6 rules, 100% detection) | Baseline→detect pattern |
| sentinel-dns | DNS threat intel (entropy + VirusTotal) | Network anomaly detection |
| bettercap | Network attack framework (WiFi/BLE/Ethernet) | Real attack tool |
| network-attack-simulator | AI-driven network pen-testing simulator | Attack simulation |
| eaphammer | WPA enterprise attacks | WiFi attack tool |
| zarp | Network attack framework | Attack tool |
| slipstream | SIP VoIP toolkit | VoIP attacks |
| nym | (unknown) | — |

---

## Detailed Summaries

### 1. attack-chain-prediction (★ Most Relevant)
- **Stack**: Python 3.11+, PyTorch 2.2, CUDA 12.2
- **Data**: 4,849 ATT&CK campaign chains + 8,437 real intrusion traces
- **Model**: 2-layer LSTM + first-order Markov + constrained beam search
- **Results**: 86% next-step accuracy, 26,051 risk-ranked forecasts, <0.2s latency
- **Risk scoring**: EPSS + CAPEC + LSTM confidence + CISA KEV + D3FEND + OCTAVE impact → 0–10 scale
- **Key insight**: LSTM alone overgeneralizes rare transitions; Markov alone lacks memory. Hybrid constrains both.

### 2. attack-coverage-dashboard
- **Stack**: Streamlit, SQLite, Python, STIX/TAXII
- **Pages**: Overview, ATT&CK Matrix heatmap, Rules, Actors, Import, Export, Data Sources
- **Coverage**: Naive + weighted (by data source availability)
- **Export**: ATT&CK Navigator JSON, PDF reports, CSV
- **130+ threat actors** parsed from STIX, per-group coverage

### 3. soc-home-lab
- **Stack**: Wazuh SIEM + Suricata NIDS + TheHive + Cortex + Grafana + Prometheus
- **Networks**: blue_net (SOC tooling) + red_net (3 vulnerable targets)
- **Detection**: 9 Sigma rules + Suricata rules + custom decoders
- **Adversary emulation**: 8-stage MITRE ATT&CK kill chain (attack_chain.py)
- **CI**: Lint + test + compile on every push
- **Quick start**: `make up && make rules && make attack`

### 4. sentinelx
- **Stack**: Python, Streamlit, Flask
- **Features**: Multi-format log parsing, PCAP analysis, stateful detections, MITRE mapping
- **Modes**: Single file, directory (incremental), auto-detect
- **Output**: JSON/text/CSV reports + Streamlit dashboard

### 5. sentinel-mavlink
- **Stack**: Python, MAVLink protocol
- **Rules**: 6 detection rules (UNKNOWN_SOURCE, INFLIGHT_DISARM, COMMAND_FLOOD, GPS_TELEMETRY, REPLAY_ATTACK, PARAM_MANIPULATION)
- **Results**: 100% detection rate, 0% false positives over 6 hours
- **Pattern**: 30-second learning phase → baseline → real-time detection

### 6. sentinel-dns
- **Stack**: Python 3.8+, AdGuard Home / Pi-hole v6
- **Method**: Shannon entropy analysis on DNS queries + VirusTotal verification
- **Versions**: Lite (no VT) + Plus (with VT)
- **Auto-blocks** confirmed threats in DNS server

### 7. bettercap
- **Stack**: Go, modular architecture
- **Capabilities**: WiFi scanning/deauth, BLE, CAN-bus, HID, Ethernet MITM
- **Features**: ARP spoofing, DNS spoofing, packet manipulation, HTTPS proxy
- **Use for**: Real network attack simulation against Idurar

### 8. network-attack-simulator
- **Stack**: Python, AI-driven
- **Purpose**: Simulated network for testing AI agents in pen-testing
- **Features**: Vulnerable network simulation, DQN agent, benchmark scenarios
- **Use for**: Training/testing attack planning algorithms
