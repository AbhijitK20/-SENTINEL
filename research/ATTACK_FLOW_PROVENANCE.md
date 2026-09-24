# ATT&CK Flow Data Provenance

## Data Sources

The `research/repos/attack-chain-prediction/Attack flows/` directory contains
STIX 2.1 Attack Flow documents from MITRE. These document real intrusion
campaigns with their ATT&CK technique sequences.

## License

MITRE ATT&CK data is released under BSD 2-Clause. The Attack Flow documents
are STIX bundles published by MITRE. The attack-chain-prediction repo's own
code has a pending license ("License status is pending institutional review"),
so its code must NOT be copied.

## Usage in SENTINEL

SENTINEL reads these local STIX bundles to extract technique sequences for
transition probability estimation. The extraction script requires the user
to supply the data directory path — no data is fetched from the network
at runtime.

## Provenance Metadata

Generated artifacts include:
- Source SHA-256 checksums
- ATT&CK version (if present in STIX objects)
- License label
- Extraction timestamp
