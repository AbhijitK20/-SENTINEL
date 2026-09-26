# Known Limitations

- Public datasets may not reflect real enterprise or CII topology.
- Attack labels may not provide complete ground-truth MITRE stage transitions.
- Flow and packet features may have different coverage depending on input source.
- Recursive rollout can accumulate prediction error.
- Feature attribution indicates model evidence, not causality.
- Probability estimates require calibration and should not be treated as certainty.
- Encrypted traffic limits payload-level interpretation.
- The prototype does not replace production SOC controls or authorize automatic response.

## Measured, not assumed

These were measured by a script in this repository. The commands are given so
each number can be reproduced rather than believed.

### The risk head over-predicts, and the imagined-state fix makes that worse

The world model's risk head is trained only under teacher forcing, so it is
never trained on a state it generated itself - which is the only input it gets
when `imagine()` rolls forward. `rssm_loss` now has an `imagined_risk` term that
closes that gap, and `dream_trajectory` returns the risk logits it needs.

It is **off by default**, because it was measured and the measurement said no.
Over 56 pre-onset cuts in the test scenarios, 4 steps ahead:

| | mean imagined risk | realized base rate | bias | Brier |
|---|---|---|---|---|
| term off (shipped) | 0.331 | 0.232 | +0.099 | 0.0815 |
| term on (weight 1.0) | 0.354 | 0.232 | +0.122 | 0.0854 |

The term is the right mechanism and it does improve the teacher-forced fit (final
epoch risk loss 0.592 -> 0.515, test F1 0.698 at recall 0.983). But the head
already over-predicts positives in general - test recall 0.98 against precision
0.54 - and training it harder on its own confident outputs amplifies that. The
root cause is the positive-class bias, not the missing imagined-state term. Fix
the bias first, then this term has something to add.

### The lateral-movement rule is close to noise on this data

`uv run python scripts/run_detector_benchmark.py`, test split, 108 windows over
3 held-out synthetic scenarios:

| rule | precision | recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| reconnaissance | 0.686 | 1.000 | 0.814 | 24 | 11 | 0 |
| lateral_movement | 0.194 | 0.259 | 0.222 | 7 | 29 | 20 |

The lateral-movement rule raises 29 false alerts for every 7 true ones, and
misses 20 of 27 positive windows. It should not be presented as a working
detector on this evidence. Reconnaissance is in reasonable shape but still
generates 11 false alerts per 24 hits, so it is not something to leave
unattended either.

These describe the synthetic generator, not a real network, and they are
threshold-sensitive: the defaults in `DetectorSet` were not tuned against this
benchmark. Tuning them on the test split would be leakage, so it has not been
done.

### Seven of the nine rules cannot be scored at all here

The generator labels windows Benign, Reconnaissance, or Lateral Movement. That
is real ground truth for two rules. The other seven - ddos, credential_abuse,
exfiltration, command_and_control, insider_threat, phishing, malware_activity -
have no corresponding stage in the data, so the benchmark reports them as not
evaluable rather than printing a precision of 0.00. A zero would read as "this
rule is bad"; the truth is "this dataset cannot judge it".
`scripts/validate_real_detectors.py` exercises those rules against a real
target, and its numbers are a plumbing check on a single host, not a field
benchmark.

### The linear transition model is barely a simulator

`make bench-world` reports the world model at +0.189 open-loop skill against a
linear transition baseline at -0.429. That comparison is not like-for-like, and
the rollout forecast now says so on its face. The linear fit's spectral norm
before stability projection is ~1.6e5, so the projection keeps about 6e-06 of
it: the "baseline" is close to a constant predictor. The world model beating it
is a real result, but it is beating a broken reference, not a rival.

### Attention and graph attention are not produced

The temporal model is a GRU and has no attention weights. No graph encoder is
trained or shipped. `Explanation.temporal_attention` and `graph_attention` exist
for contract compatibility and are always `None`. The GAT that once lived in
`sentinel/graph/gnn.py` was deleted because nothing could ever call it.

This file must be updated whenever an evaluation or demo reveals a new limitation.
