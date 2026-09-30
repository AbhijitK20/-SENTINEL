# Real CIC-IDS2017 release bundle

Trained on **4,899 real windows** aggregated from
cic-ids2017/TrafficLabelling (8 day CSVs) at 60s windows / 30s stride,
read from the committed derived aggregate rather than re-windowing the source.

| | |
|---|---|
| dataset | `cic-ids2017-trafficlabelling-derived-v1` |
| windows | 4,899 |
| features | 67 |
| scenarios | 19 train / 6 val / 7 test |
| seed | 42 |
| generated | 2026-09-29T15:59:43+00:00 |

Threshold calibrated on the validation split only. The deployment baseline is
fitted on a benign reference slice of train, disjoint from evaluation.

## Citation

Sharafaldin, Lashkari & Ghorbani, 'Towards Generating New Intrusion Detection Datasets and Intrusion Traffic Characterization', ICISSP 2018. https://www.unb.ca/cic/datasets/ids-2017.html

Regenerate with `scripts/export_derived_windows.py` then this script.
