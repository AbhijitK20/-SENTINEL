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
each number can be reproduced rather than believed. Run `make bench-calibration`
for the calibration table below.

### The lead-time median dropped every miss from the denominator

`evaluation._summarize` computed `measured_median_lead_windows` as the median
over rows that *earned lead credit*:

    leads = [r.lead_windows for r in rows if r.lead_windows is not None]

Every attack the system never warned about was removed before the median was
taken. That is survivorship bias wearing a statistic - the harder cases leave the
sample, so the surviving number measures how fast the system is *when it works*
while reading as how fast it is.

`src/sentinel/survival.py` treats detection as the right-censored problem it is.
Kaplan-Meier with Greenwood variance, a median with a Brookmeyer-Crowley
pointwise interval, and a two-sample log-rank test, all in numpy plus
`math.erfc`. `evaluate_detection_survival` reports it next to the old figure so
the two can be compared rather than the better one being chosen.

**Measured on current data, the fix does not change the headline - and that is
the finding, not a disappointment.** On the test split, 18 attacks had a
realised future and **all 18 were detected**, so there were zero censored units
for Kaplan-Meier to account for. Both statistics read 0.0 windows.

What did change is the *uncertainty*, which the point estimate never carried:
the interval is reported, and it is what makes "0.0" interpretable. A median of 0
means detection fires in the same window the attack becomes observable - the
documented limitation - and a CI shows how little the data can distinguish that
from being a window or two late. The structural fix matters the moment anything
is missed, which the withdrawn real-data run and any harder dataset will do.

So: the machinery is correct, tested against the closed-form identities, and
currently confirms rather than corrects. That is worth saying plainly, because
"we fixed the metric" would have been the more flattering and wrong summary.

### Three features are indistinguishable from 98, and the data cannot really tell

`make bench-telemetry`. The 98-feature schema splits by collection cost:

| tier | what it needs | features |
|---|---|---|
| flow_window | flow records, window aggregates only | 43 |
| flow_per_flow | per-flow values retained, not just aggregates | 24 |
| packet | **packet capture on the sensing interface** | 31 |

A third of the feature set requires a sensor on the wire. So the first ablation
was run with forward selection scored on the training split, and a paired
bootstrap on the untouched validation split:

| features | Brier (lower better) | tiers | 95% CI on loss | indistinguishable? |
|---|---|---|---|---|
| 3 | 0.0212 | flow_window, packet | -0.0017 to +0.0123 | yes |
| 5 | 0.0220 | flow_window, packet | -0.0016 to +0.0161 | yes |
| 8 | 0.0220 | all three | -0.0001 to +0.0143 | yes |
| 12 | 0.0190 | all three | -0.0002 to +0.0058 | yes |
| 20 | 0.0177 | all three | -0.0003 to +0.0023 | yes |

"Loss" is `subset - full` on Brier, so a *positive* interval means the smaller
feature set is measurably worse and a negative one that it is measurably better;
either way an interval containing zero means the split cannot tell them apart.
The recommended profile is **3 features - `packets_max`, `rst_count`,
`bytes_max`** - against 98.

**That is a much weaker claim than it looks, and the reason matters.** The
validation split is 68 windows, and every interval above is wide enough to
straddle zero for wildly different feature counts. The tool says "no measurable
loss on this split", not "equally good", and the report says so in the same
words. A reader should treat this as *the data cannot distinguish 3 from 20*,
which is a statement about 68 windows rather than about the problem.

Two method notes, both because the first attempt produced nonsense:

- Ranking by coefficient magnitude gave a **non-monotone** curve - 8 features
  indistinguishable while 12 was measurably worse, which is incoherent for a
  nested family. Coefficient magnitude ignores collinearity, so it is not a
  ranking of usefulness. Greedy forward selection on the training split replaced
  it and the curve became coherent.
- The metric is **Brier, not F1**, because the bootstrap needs a per-window
  quantity and F1 is not additive over windows. A bootstrap over F1 would be
  measuring the resampling.

The operational prize is real but unproven: 31 of 98 features need packet
capture, and the small sets that qualify do not. Confirming that on real traffic
is the thing to check first when CIC-IDS2017 becomes available.

### The baseline is well calibrated; the world model's risk head is not

`scripts/run_calibration_report.py`, ten synthetic scenarios, test split:

| model | n | base rate | mean p | bias | ECE | Brier | skill |
|---|---|---|---|---|---|---|---|
| baseline | 68 | 0.265 | 0.297 | +0.028 | 0.043 | 0.029 | +0.853 |
| world model | 264 | 0.227 | 0.359 | +0.097 | 0.097 | 0.070 | +0.600 |

The baseline is fine, and the report says so rather than manufacturing a problem.
The world model's head is not, and its reliability table shows where it fails:

| predicted | observed | gap |
|---|---|---|
| 0.50-0.60 | 0.000 | -0.554 |
| 0.70-0.80 | 0.000 | -0.752 |
| 0.80-0.90 | 0.091 | -0.775 |
| 0.90-1.00 | 0.843 | -0.144 |

The ranking is good - observed frequency rises monotonically with predicted
probability. The *scale* is wrong: whenever the head said 0.5-0.9, the event
essentially never happened, so a consumer reading "65% likely" was being told
that about events with a 0% observed rate.

### Isotonic recalibration helps the error rate, but not reliably the Brier score

`src/sentinel/isotonic.py` fixes that failure mode: a monotone map from score to
observed frequency, which is exactly what a well-ranked, badly-scaled classifier
needs. Temperature scaling would not - one parameter cannot turn a sigmoid into a
step. It also cannot change which window outranks which, which is checked rather
than assumed.

Tried on two fixtures. It improved **ECE on both** and **Brier on only one**:

| fixture | Brier | ECE | shipped? |
|---|---|---|---|
| `w0`-`w9`, seed 23 | 0.0432 -> 0.0382 | 0.083 -> 0.035 | yes |
| `cal00`-`cal09`, seed 23 | 0.0420 -> **0.0568** | 0.059 -> 0.050 | **no** |

So it is **gated**. `_risk_recalibration` fits on validation, measures on test,
and ships the curve only if held-out Brier improved *and* the ranking is
unchanged. Otherwise the head ships as trained, and
`risk_recalibration_outcome` records that it was tried and rejected.

The committed release bundle predates this work, so it carries no
`risk_recalibration` field at all and the loader takes the untuned path. That is
the same outcome by omission rather than by measurement, which is a weaker
statement than the table above: the gate has not actually been exercised on the
published artifact. `models/release/v1` is re-exported in Sprint 10, at which
point the shipped bundle will either carry a curve that passed the gate or
record the rejection explicitly.

### The head is saturated, so recalibration cannot be fine-grained

The head is trained by binary cross-entropy on a separable problem, so it emits
only a handful of distinct values. The fitted curve has 253 blocks over 264 points
but only about three *levels*: it maps 0.55, 0.65 and 0.75 all to 0.50. No amount
of calibration data invents gradation the head never learned. The fix for that
belongs in the loss - label smoothing, or accepting that the head is a classifier
rather than a probability estimate - not in post-hoc scaling.
`tests/test_recalibration_gate.py` pins the saturation so the explanation cannot
quietly become wrong.

### A step in the true rate is not reliably recovered

If the calibration target jumps, isotonic places the jump only where a block
boundary happens to land. Across six seeds on a step at 0.80, fits were equally
likely to straddle it at 2 000 points per fit. More data helps on average; it does
not make the step reliable. That is why adoption is decided by held-out gain and
never by whether the curve "looks right".

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

### The shipped PSI bands fire on ordinary noise, so `band_of` cannot be trusted

`make bench-drift`. `sentinel.drift` bands PSI at **0.10** ("moderate") and
**0.25** ("significant"). Those are the conventional numbers and they are quoted
without the sample size that produces them, so nothing in this codebase could say
what false-alarm rate they buy. The API exposes them through `/compare` and the
backtest script calls `compare_feature` directly, so this is not a dormant
constant.

Measured on **400 held-out blocks of iid Gaussian noise** - no drift in them at
all - at 30 windows per block:

| band | worst of 3 features | median single feature |
|---|---|---|
| 0.10 | **100%** | **92%** |
| 0.25 | **100%** | 51% |

**Every block exceeds both bands.** So `band_of` answers `significant` for
ordinary noise, and a caller cannot distinguish a real drift from a quiet Tuesday.
The single-feature column matters: the problem is the constant, not the
aggregation, because 0.10 already fires on 92% of one feature's own held-out
blocks.

The fix is to band against a threshold calibrated to the data's own null, which is
what `drift_monitor.DriftMonitor` does, and it is **not applied** to
`sentinel.drift` here because that changes an API-visible value and needs a
version bump. Until then, `band_of` should be read as a rough indicator of
*magnitude* and never as a decision. A test pins the measured rate so a fix will
fail loudly.

### A drift monitor on this data cannot tell a stealthier attacker from a new cohort

The same run asks the operational question: train on one attack style, then meet
another - same generator, lateral phase shortened from 8 minutes to 3, so the
attacker is doing the same thing faster and quieter. Everything is fitted on
pre-shift windows only.

| windows/block | false alarms pre-shift | detections post-shift | delay |
|---|---|---|---|
| 10 | 117/127 | 221/290 | 0 |
| 30 | 57/107 | 91/290 | 0 |
| 60 | 38/77 | 116/290 | 13 |
| 120 | 2/17 | 174/290 | 15 |

**The false-alarm rate before the shift is as high as the detection rate after
it.** The monitor is already screaming when nothing has changed, so its "detection
delay" is not a useful number on this data - the delay is 0 because the alarm was
already on. Longer blocks cut the false alarms and cost nothing in delay here, but
even at 120 windows there are only 17 pre-shift blocks to judge from, which is why
the block size is *stated* at 30 rather than chosen from this table: picking the
row that looks best would be selecting on a 17-sample zero.

The underlying cause is that a 10-window block lies almost entirely inside one
scenario, so PSI over many features is measuring *which scenario it is looking at*
rather than whether the process changed. This feature set needs far longer
aggregation, or a handful of features, before a drift tripwire means anything.

### Two other things the drift run measured

- **Coverage barely moved under the shift**: 92.6% before, 90.3% after, against a
  promised 90%. The caveat in `ConformalInterval` - "not valid under distribution
  shift" - is real in principle and was *not* observed here. That is a null result
  on one synthetic shift, not evidence the caveat can be deleted, and the two
  cohorts differ in attack rate as well as style so the comparison mixes two
  effects.
- **Brier degraded mildly**, 0.0286 to 0.0327, on a cohort whose attack rate had
  also nearly halved. A model evaluated on a different base rate is being asked a
  different question, so this is not a clean measure of drift damage either.

### Self-supervised pretraining made it worse, and the reason is instructive

`make bench-labels`, 12 synthetic scenarios, 7 training scenarios, scored on the
68-window validation split. A masked-feature autoencoder (98 -> 16 -> 98) is
fitted on every training window **without reading a label**, then the same nested
label budgets are spent on its representation and on the raw features.

| method | Brier trained on everything | Brier from one scenario | headroom |
|---|---|---|---|
| scratch (98 raw features) | **0.0256** | 0.0701 | +0.0444 |
| pretrained (16 latent dims) | 0.0678 | 0.1080 | +0.0402 |

**The representation loses, by a factor of 2.6 on Brier.** Its reconstruction loss
fell from 0.7816 to 0.0900, so the encoder did learn the feature structure well -
it just learned the wrong thing. Reconstructing flow features is a *variance*
problem: the dominant directions in a 98-dimensional flow summary are the busy
ones, total bytes and packet counts. The infiltration signal lives in a
different, smaller direction, and a 16-wide bottleneck trained to rebuild the
busy dimensions has no reason to preserve it. **Reconstruction is not
discrimination**, and on this feature set the two point in different directions.

The second finding is the one that makes the first interpretable. Headroom is
+0.0444 for the raw features: one labelled scenario is *not* enough here, and the
curve climbs steadily from 0.0701 to 0.0419 by six scenarios. The label question
is therefore live on this data, which means the pretraining result is a real
negative rather than an artefact of a saturated task.

What this does not establish: anything about masked-feature pretraining in
general. It is one architecture, one latent width, one synthetic generator. A
contrastive objective over *windows* rather than features, or a wider bottleneck,
could plausibly close the gap, and neither was tried.

The verdict column is mostly "at ceiling" and that is the small-split problem
again: 68 validation windows is too few for the paired bootstrap to separate a
4-scenario model from a 7-scenario one. Only the single worst point is
distinguishable. The intervals are printed rather than summarised to "no
difference".

### The telemetry budget is not the same as the label budget

Two superficially similar questions, opposite answers, and the pairing is the
useful part. Sprint 5 found that 3 of 98 features lose nothing measurable; this
sprint finds that 1 of 7 scenarios is worth 0.0444 Brier. So the features are
highly redundant while the *scenarios* are not - a single campaign teaches
something a second campaign still teaches again. Anyone reading the Sprint 5
result as "this needs almost no data" would be wrong in the dimension that
actually binds.

### The lateral-movement rule can be evaded by going slower, not quieter

`make bench-evasion`, 16 real attacking windows from the test split, with six
windows of history each. Every detector was attacked with a closed set of
executable strategies and the alert was re-measured.

**Result: one of nine is evadable.**

| detector | cheapest feasible evasion | extra bytes | extra windows |
|---|---|---|---|
| lateral_movement | **throttle the transfer** | **0** | **0.8** |
| reconnaissance | none found | - | - |
| credential_abuse | none found | - | - |
| ddos | none found | - | - |
| insider_threat | none found | - | - |
| exfiltration | none found | - | - |
| command_and_control | none found | - | - |
| malware_activity | none found | - | - |
| phishing | none found | - | - |

`detect_lateral` scores bytes across internal edges unseen in the last five
windows. An attacker who sends the same payload more slowly keeps every window
under the band, and pays **nothing in bandwidth and about 0.8 windows of extra
dwell time**. That is the whole cost.

This is the same rule that scored precision 0.194 in Sprint 4's detector
benchmark, and the two findings are the same finding from two directions: a
narrow byte band is easy to sit under in both directions, and it fires on benign
hops as readily as on attacks. **The rule is not fit for purpose as written** -
either it needs a ratio or a rate rather than an absolute byte count, or it needs
to be combined with something the attacker cannot simply slow down.

Two limits on this analysis, both stated in the report it produces:

- The strategies are **hand-enumerated** from each rule's own definition, so
  this prices the *known* evasions. A signature nobody anticipated is not here,
  and "none found" means "none of the moves we thought of", not "impossible".
- Costs are bytes and windows, not currency. Converting to money needs a
  deployment's own numbers, and inventing a rate would be the same mistake as the
  removed capacity table's invented throughput.

One structural note worth keeping: on these windows the `lateral_movement` alert
arrives as `sequence-prediction` from the sequence detector, not from the byte
rule. The evasion is therefore *upstream* - stay under the reconnaissance
threshold - rather than a weakness in the byte band. The report attributes each
alert to the rule that produced it for exactly this reason; a byte-level search
against a history-based rule measures nothing.

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
