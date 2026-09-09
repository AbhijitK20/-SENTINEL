# Dataset Plan

## Candidate Sources

- CIC-IDS2017/2018: broad labelled flow records and attack categories.
- CTU-13: scenario-oriented botnet traffic useful for temporal replay.
- UNSW-NB15: independent validation source.
- CICIoT2023: IoT-oriented validation if compatible.
- LANL Authentication Dataset: authentication relationships where licensing and access permit.
- DARPA intrusion datasets: historical validation context where usable.

## Selection Criteria

The primary dataset must have timestamps, stable scenario or session identity, enough benign context, attack labels, and a defensible way to derive future transition targets. A secondary dataset should test transfer beyond the primary source.

## Flow And Packet Coverage

The pipeline supports:

- Flow-level records: addresses, ports, protocol, flags, bytes, packets, duration, IAT statistics, bidirectional ratios.
- PCAP-derived records: TTL, TTL variance, TCP window size, fragmentation, payload-size distribution, scan signatures, retransmissions.

If a dataset does not contain both levels, the limitation must be recorded. We must not fabricate a relationship between unrelated CSV and PCAP samples.

## Label Strategy

Labels will be derived from timestamped attack annotations and documented stage rules. If a dataset does not support reliable stage labels, it can support binary or trajectory validation but must not be presented as ground truth for every MITRE stage.

## Leakage Controls

- Split by scenario, campaign, day, or source rather than random adjacent rows.
- Do not aggregate future events into a current window.
- Fit normalizers only on training data.
- Keep entity identifiers and labels out of unintended features.
- Record all transformations and dataset versions.

## Reproducibility

Dataset acquisition instructions, checksums, preparation configuration, feature coverage, and known licensing constraints must be documented before benchmark claims are published.
