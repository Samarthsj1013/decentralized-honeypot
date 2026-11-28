# DAHIN Experimental Results

This file separates measured software experiments from synthetic assumptions
and operator-reported historical observations. Values are not claims of
real-world attack detection or defense effectiveness.

## Baseline software verification (2026-11-27)

| Check | Scope | Result |
|---|---|---|
| Backend pytest | Isolated source copy; databases and keys excluded; Cowrie, Suricata and Zeek fixtures explicitly verified | 356 passed, 0 failed, 1 Starlette/httpx deprecation warning; 117.88 s |
| Frontend tests before upgrade changes | Complete Node test suite | 27 passed, 0 failed, 0 skipped |
| Production build before upgrade changes | Vite 6.4.5, public demo true, relative `/api/v1`, temporary output | Passed; 35 modules |

## Historical controlled Cowrie observation

Previously reported result: 15 observations; 3 successful emulated logins; 6
session events; 0 failed authentication events; 0 command attempts; anomaly
index 0.438; cluster 4; model `attacker-profile-synthetic-v1`; predicted
category `authentication_probing`. The public snapshot preserves this
historical operator-verified observation. It is not a ground-truth label.

The reported aggregate was reconstructed in a regression test: with 15
observations, three successful logins, no failed logins, and no command
attempts, the synthetic classifier's `authentication_probing` vote is now
gated to `unknown`. This does not rewrite the public snapshot or claim that
the historical session was benign; it records that evidence for the synthetic
authentication-probing class was absent.

## Existing synthetic experiment methodology

`backend/app/experiments/service.py` pairs baseline/adaptive scenario runs
using the same generated event rows and derived seeds. Ground truth is the
scenario generator's explicit synthetic `suspicious` flag. Metrics therefore
describe generated scenarios only. The reaction model's engagement
probabilities are assumptions. `unique_decoys_accessed` and memory are
unavailable; current documentation reports no confidence intervals for its
bounded samples. A follow-up experiment was run on 2026-11-27 after correcting
the per-scenario timer so temporary incident-store initialization is excluded.

## Public Cowrie dataset distribution review

The privacy-filtered processor was run against the public CyberLab file
`cyberlab_2019-05-18.json.gz` from the [Zenodo CyberLab record](https://zenodo.org/records/3687527)
(DOI `10.5281/zenodo.3687527`, CC-BY-4.0). The sample is a single daily export,
not an independent or representative test corpus. The compressed input stayed
under `%TEMP%`; only the aggregate JSON result below is retained in this
repository. Per-session numeric feature rows were written to `%TEMP%` and were
not retained.

| Measurement | Observed |
|---|---:|
| Input sessions | 7,465 |
| Processed sessions | 7,465 |
| Duplicate session keys skipped | 0 |
| Events in processed sessions | 35,742 |
| Trusted behavior labels | Unavailable |
| Accuracy / precision / recall / F1 | Unavailable: no trusted labels |
| Observed MD5 | `6428bc0c9e4c83eecd78a1c01728f171` |
| Observed SHA-256 | `b681316de5ff58f8cae385fd4a2232d93ccdeb0b117ef58668195df5797d9c45` |

Event counts were: login failure 2,023; successful login 5,056; session
connect 7,467; session close 7,467; session metadata 5,356; command attempt 6;
file download 29; and other/unmapped events 8,338. `duplicate_sessions_skipped`
is based on repeated top-level session keys; the source did not expose a
separate duplicate field for these events.

As a descriptive composition check, the event shares were: session connected
20.891%, session closed 20.891%, other/unmapped 23.328%, login success
14.146%, session metadata 14.985%, login failure 5.660%, file download
0.081%, and command attempt 0.017% (denominator 35,742 events). These shares
quantify the observed log mix only; they are not a real-versus-synthetic
feature-distance statistic because the source aggregate does not preserve
per-session values for the classifier's 30-feature schema.

### Distribution-shift assessment

The source itself describes collection from roughly 50 university/company
nodes between May 2019 and February 2020, with Cowrie 1.6.0 low-interaction
operation through 2019-11-08 and Cowrie 2.0.2 thereafter, including a tagged
high-interaction pool. The reviewed May 18, 2019 daily sample predates that
upgrade and is therefore a single-date, low-interaction-era Cowrie sample.
Its observed event mix is heavily weighted toward session lifecycle and
authentication: 2,023 failed and 5,056 successful login events, against 6
command attempts in 7,465 sessions. The synthetic training data instead has
six deliberately generated behavior categories and labels derived from its
feature thresholds. These populations and label processes differ materially;
the source has no trusted behavior labels.

No numeric population-stability/feature-distance score is reported. The
retained CyberLab artifact contains only aggregate counts and model-vote
quantiles; the privacy-filtered per-session feature export was temporary and
is no longer present. A fresh download was attempted on 2026-11-28 but this
execution environment could not reach Zenodo. Consequently this assessment is
descriptive, not a reproducible quantitative feature-shift calculation, and
the unlabeled prediction counts must not be interpreted as validation metrics.

With the synthetic model trained at 80 examples/category and seed 2026, raw
unlabeled predictions were `authentication_probing=70` and
`suspicious_session=7,395`. After the evidence gate: 69 authentication
probing, 1 suspicious session, and 7,395 unknown. These are output counts,
not attack labels. The maximum-vote fraction median was 0.3625 (p05 0.3625,
p95 0.50625); it is not calibrated confidence. The complete sanitized
aggregate is [`experiments/results/cyberlab_2019-05-18_summary.json`](../experiments/results/cyberlab_2019-05-18_summary.json).

## Synthetic model holdout comparison

Command:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
python experiments/evaluate_profile_models.py `
  --output experiments/results/profile_model_evaluation_20261127.json `
  --samples-per-category 200 `
  --train-seed 20261127 --validation-seed 20261128 --test-seed 20261129
```

Train, validation, and test data were generated independently from distinct
seeds (1,200 rows in each split; selected candidates were refit on 2,400
train+validation rows). Validation macro-F1 selected parameters. A collision
check found 1,042, 1,041, and 1,041 unique vectors within the train,
validation, and test splits, respectively. There were 41 exact vectors shared
between train/validation, 41 between train/test, and 40 between
validation/test; every shared vector had the same label in both splits. The
collisions come from low-variance/discrete synthetic rows and mean that
distinct seeds do not guarantee distinct feature examples. They are a source
of optimism but do not alone explain the perfect score. The stronger causes
are the generator's deterministic class-specific feature ranges, feature-label
circularity, and the rule baseline's mirror of class-defining thresholds. On
the
independent generated test split, the Random Forest, decision tree, logistic
regression, and fixed evidence-rule baseline each measured accuracy 1.0,
macro-F1 1.0, macro one-vs-rest false-positive rate 0.0, and macro
false-negative rate 0.0. The rule baseline matched the generator's defining
feature thresholds exactly, so perfect synthetic scores primarily confirm
the ease/structure of those generated labels. They do not establish model
utility or real-world detection effectiveness. Full per-class results,
confusion matrices, validation trials, parameters, and timings are stored in
[`experiments/results/profile_model_evaluation_20261127.json`](../experiments/results/profile_model_evaluation_20261127.json).

## Independent synthetic shift challenge (2026-11-28)

The perfect holdout scores prompted a pre-specified stress evaluation. A latent
dominant scenario label was selected before feature generation. A separate
episode sampler then introduced overlapping secondary behaviors, lower and
broader count distributions, mixed feature aggregates, 8% per-feature missing
aggregates (encoded as the schema's zero value), and count noise. Models and
hyperparameters were fixed from the earlier synthetic validation; no tuning
used challenge rows. There were 200 training rows per class from the original
generator and 200 challenge rows per class from the alternate generator
(1,200 rows in each split); 1,177 challenge feature rows were unique. This is
out-of-generator synthetic stress testing, not external or operational ground
truth.

| Candidate | Accuracy | Macro F1 | Macro OVR FPR | Macro OVR FNR |
|---|---:|---:|---:|---:|
| Random forest | 0.8600 | 0.8601 | 0.0280 | 0.1400 |
| Decision tree | 0.7525 | 0.7573 | 0.0495 | 0.2475 |
| Logistic regression | 0.5358 | 0.5176 | 0.0928 | 0.4642 |
| Fixed evidence rules | 0.4825 | 0.5165 | 0.1035 | 0.5175 |

On this authored challenge, random forest macro-F1 exceeded the fixed rules by
0.3437 (34.4 percentage points); logistic regression was approximately tied
with the rules. This supports measurable value only on this generated stress
set. Labels are still authored latent scenarios, missingness is collapsed to
zero by the current schema, and the CyberLab data has no trusted labels. No
real-world classifier conclusion follows.

Reproduce with a unique output path:

```powershell
$challenge = Join-Path $env:TEMP ('profile-challenge-' + [guid]::NewGuid().ToString('N') + '.json')
python experiments/evaluate_profile_challenge.py --output $challenge `
  --samples-per-category 200 --train-seed 20301127 --test-seed 20301128
```

## Paired static/adaptive/closed-loop run (2026-11-27)

The reproducible command was:

```powershell
$out = Join-Path $env:TEMP ('dahin-paired-' + [guid]::NewGuid().ToString('N') + '.json')
python experiments/run_deception_comparison.py --output $out `
  --seed 20261127 --repetitions 5
```

All 150 mode-runs completed: 10 scenarios × 5 repetitions × 3 modes. The
baseline and adaptive modes use the same seeded initial events per scenario;
closed loop also processes simulated follow-up records. The table gives
actual aggregate results from the run; processing latency includes local
per-event incident SQLite work but excludes store initialization, synthetic
generation, model classification/training, and result persistence.

| Mode | Runs | Events | TP / FP / FN | Detection coverage | FPR / FNR | Incident rate | Median virtual detection | Adaptation frequency | Simulated engagement | Mean event processing |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Static baseline | 50/50 | 245 | 75 / 0 / 150 | 33.3% | 0% / 66.7% | 100% | 2.5 s | 0% | 28% | 26.11 ms/event |
| Adaptive | 50/50 | 245 | 90 / 0 / 135 | 40.0% | 0% / 60.0% | 100% | 2.0 s | 20% | 30% | 26.35 ms/event |
| Closed loop | 50/50 | 255 | 95 / 0 / 140 | 40.4% | 0% / 59.6% | 100% | 2.0 s | 12% | 20% | 23.86 ms/event |

Mean synthetic interaction depths were 5.18, 5.24, and 5.10 events; median
virtual durations were 5.0 seconds in all modes. Closed-loop mean reward was
0.3876. Reaction outcomes and durations are seeded scenario outputs, not
observed attacker activity. The zero false-positive result only describes
the generated benign rows and this detector; it is not an operational false
alarm estimate. The retimed per-run output is
[`paired_deception_20261127_retimed.json`](../experiments/results/paired_deception_20261127_retimed.json).

### Paired uncertainty and engagement interpretation (2026-11-28)

Run-level outcomes were paired by scenario and repetition. A 20,000-draw
scenario-cluster bootstrap resampled the ten scenario clusters with replacement
and kept each scenario's five repetitions together. On this fixed 150-run
artifact, the adaptive-minus-baseline mean per-run detection-coverage change
was +4.58 percentage points (95% interval 0.00 to 11.25); closed-loop minus
adaptive was +1.03 pp (-0.00 to 2.46). Adaptive-minus-closed-loop engagement
was -10.0 pp (-28.0 to +4.0). The interval includes zero, so this sample does
not show that closed loop systematically reduces engagement. Intervals reflect
only this ten-scenario generator and are coarse with ten clusters.

Observed engagement was 14/50 static, 15/50 adaptive, and 10/50 closed loop.
The adaptive profile path selected its mapped recommendation; the contextual
policy selected `neutral_response` on 43/50 closed-loop runs and can explore or
exploit other bounded choices. The simulator assigns reaction probabilities
based on selected-strategy/recommendation matches (with special cases for
unknown and repeated-connection contexts) and uses a deterministic seed. The
lower closed-loop result is therefore an outcome of this policy plus the
synthetic reaction assumptions and particular seeded draws, not evidence about
actual attacker engagement or a proven policy defect.

Recalculate paired effects from the retained run-level artifact with:

```powershell
$pairedAnalysis = Join-Path $env:TEMP ('paired-analysis-' + [guid]::NewGuid().ToString('N') + '.json')
python experiments/analyze_deception_comparison.py `
  --input experiments/results/paired_deception_20261127_retimed.json `
  --output $pairedAnalysis
```

## Multi-node local replication validation

`python -m app.network.multi_node_demo --nodes 4` ran with separate local
processes, temporary node databases, unique test Ed25519 keys, and direct
localhost HTTP. Signed imports were stored pending; repeated delivery was
idempotent; modified records returned HTTP 400; a third node without publisher
trust returned HTTP 403; a receiver reported unavailable while offline, then
stored a new pending record after restart. The publisher retained its local
record. Database identities and key fingerprints were distinct. Transfer
times in the current run were approximately 1,154 ms and 783 ms; these are
machine-dependent. This is not consensus, relay, multi-machine transport, or
Byzantine fault tolerance.

## Regression checks (2026-11-27)

- `backend/tests/test_real_cowrie_dataset.py`: 7 passed after rejecting an
  empty JSON root and running pytest with an explicit writable temp base.
- `backend/tests/test_profiling_evaluation.py backend/tests/test_profiling.py`:
  34 passed before replacing the scikit-learn single-class warning with a
  direct measured-recall calculation; the latest full-suite result is in
  `UPGRADE_PROGRESS.md`.
- `backend/tests/test_experiments.py backend/tests/test_public_demo.py`: 53
  passed after updating the public sanitized research snapshot and correcting
  per-event timing boundaries.
- Frontend browser sandbox: 28 tests passed after making the false-positive
  metric unavailable when independent event predictions are absent. The
  latest frontend/build result is in `UPGRADE_PROGRESS.md`.

## Latest full regression (2026-11-27)

The corrected source-only copy procedure retained the three deliberate parser
fixtures and verified their byte lengths before test collection. The full
backend run reported **389 passed, 0 failed, 0 skipped, 1 warning** in
156.51 seconds. The warning is Starlette's deprecation notice for using
`httpx` with `starlette.testclient`. The complete frontend suite reported
**28 passed, 0 failed, 0 skipped**. The public build used
`VITE_PUBLIC_DEMO=true` and `VITE_API_BASE_URL=/api/v1`, transformed 35
modules, and succeeded with output under `%TEMP%`. These checks are recorded
again with exact commands in [`UPGRADE_PROGRESS.md`](UPGRADE_PROGRESS.md).

## Resumed experiment reruns (2026-11-28)

After the outbound bearer-transport change, a fresh source-only copy ran the
same seeds and repetition count. The paired experiment again completed 150 of
150 runs. This run measured detection coverage of 33.33% static, 40.00%
adaptive, and 40.43% closed loop; generated-control false-positive rate was
0% for each; simulated engagement was 28%, 30%, and 20%; and mean synthetic
interaction depth was 5.18, 5.24, and 5.10 events. Average local event
processing was 25.23, 24.82, and 22.44 ms respectively. These machine-specific
timings differ from the earlier run; both results describe the same seeded
synthetic methodology and are not field performance.

The independent-seed synthetic holdout was also rerun: 1,200 test examples
from a separate generator seed after 2,400 train-plus-validation examples.
Random forest, decision tree, logistic regression, and the evidence-rule
baseline each again measured 1.0 accuracy and 1.0 macro-F1. These values are
strictly synthetic-label agreement and do not resolve the lack of trusted
real-world labels or the documented distribution difference.

The final 2026-11-28 analysis reran the paired bootstrap on the retained
150-run artifact. Adaptive minus closed-loop engagement remained -10.0
percentage points with a 95% interval of -28.0 to +4.0; the interval includes
zero and does not establish a systematic difference. No new simulator runs or
real attacker data were introduced for this analysis.
