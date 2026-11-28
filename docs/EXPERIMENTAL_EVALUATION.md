# Offline adversary experiments

## What the harness does

`backend/app/simulation/adversary.py` produces deterministic normalized records
for ten synthetic behaviors. It does not open sockets, ingest these records
through the live telemetry API, or contact a target. `backend/app/experiments/`
orchestrates paired runs, stores results in a dedicated SQLite database, and
renders reports from persisted summaries. The existing five-scenario
interaction simulator and `/evaluations` API remain separate and unchanged.

Scenario names are `reconnaissance`, `ssh_authentication_probing`,
`repeated_failed_authentication`, `successful_auth_suspicious_activity`,
`multi_port_probing`, `multi_protocol_activity`, `repeated_session_behavior`,
`multi_sensor_correlated_activity`, `low_and_slow_activity`, and
`mixed_benign_suspicious_traffic`.

Each scenario/repetition has a derived deterministic seed. The baseline and
existing adaptive detector consume the same initial generated records and the
same seeded reaction random draw. Both modes record a synthetic engagement
outcome under the explicit strategy reaction model, while detection metrics
continue to use the same initial event set. The
baseline applies fixed rule thresholds. The adaptive mode runs the existing
versioned feature extractor and synthetic Random Forest model, obtains a
recommendation from the existing profiling policy, records its strategy and
reason, then changes only simulation-local thresholds. No real adaptation
history, decoy registry, operational event store, or ledger is modified.
Incident detection is exercised through the existing incident correlator with
an isolated temporary SQLite database for each scenario-mode run.

The optional `closed_loop` mode adds a simulation-local contextual policy,
attacker reaction, and reward feedback. Its bounded strategy library consists
of `static_baseline`, `expanded_decoy_path`, `credential_decoy`, `file_decoy`,
and `neutral_response`. The policy uses deterministic epsilon-greedy selection
with epsilon 0.15, a +0.25 bonus for the existing profile recommendation, and
per-experiment mean rewards clamped to [-1, 1]. It records selected strategy,
policy version, reaction, and reward. The same seeded reaction model records
engagement for baseline and adaptive modes; their detector metrics still use
only the shared initial event set. Closed-loop mode also feeds its simulated
follow-up events into that run's detector measurement. The reaction model
includes abandonment and deliberately low-engagement cases.

For paired baseline/adaptive comparison, the synthetic engagement model uses a
0.62 seeded engagement probability when the selected strategy matches the
profile recommendation and 0.28 otherwise. It includes explicit 0.20
probabilities for unknown/neutral and 0.10 for the repeated-connection/file
decoy case. These are declared simulation assumptions, not learned from
telemetry. `simulated_interaction_depth` counts initial generated records plus
simulated follow-up records. `simulated_session_duration_seconds` is the
virtual timestamp span of those records; it is not wall-clock dwell time.
Unique decoys accessed is unavailable because synthetic events have no
validated decoy asset identifiers.

The seeded scenario and repetition pair the same initial event rows and
reaction draw for baseline and adaptive runs. Use multiple repetitions and a
fixed seed when comparing changes. `adaptation_frequency` is the share of
adaptive runs that selected a non-static strategy; it does not count multiple
within-session strategy transitions. This experiment database contains only
synthetic results. External Cowrie/Zeek/Suricata telemetry remains in the live
event/profile/ledger stores and does not silently enter this experimental
dataset.

Reward is the measured synthetic utility proxy
`0.40*detection_coverage + 0.15*engagement_rate + 0.20*incident_detected +
0.20*continued_engagement - 0.25*false_positive_rate -
0.10*follow_up_event_overhead - strategy_resource_cost`, clamped to [-1, 1].
This is a research simulation score, not a cybersecurity effectiveness score.
It uses explicit synthetic assumptions and does not learn from operational
telemetry.

The `closed_loop` mode is opt-in; existing requests still default to `baseline`
and `adaptive`. Select all three modes for comparison. The response adds
closed-loop aggregate values separately. Detection-coverage adaptation
effectiveness remains adaptive minus baseline; simulated engagement has a
separate paired comparison metric.

Ground truth is the generator's explicit per-event `suspicious` label. The
rule threshold detector's event flags are the predictions used for TP, FP,
and FN. The existing ML category is recorded separately as a model output; it
does not become ground truth. Incident detection is the output of the existing
correlation service and is reported separately from event-level predictions.

## Metric definitions

For a mode, summed over its requested scenario repetitions:

| Metric | Definition |
|---|---|
| Detection coverage | True-positive synthetic events / ground-truth suspicious events. |
| Event capture rate | Locally processed generated events / generated events. This is an in-process simulator measure, not sensor capture or network delivery. |
| Incident detection rate | Suspicious scenario runs with an incident / suspicious scenario runs. |
| Detection latency | Median virtual event timestamp offset from scenario start to the first event flagged by the threshold detector; detected runs only. |
| False-positive rate | Benign events flagged / all benign events. Unavailable when no benign events exist. |
| False-negative rate | Suspicious events not flagged / all suspicious events. |
| Scenario completion rate | Completed mode-runs / requested mode-runs. |
| Adaptation frequency | Adaptive and closed-loop runs that selected a non-static strategy / completed runs in that mode. It is a strategy-selection rate, not a count of within-run transitions. Baseline is zero. |
| Adaptation effectiveness proxy | Adaptive minus baseline synthetic detection coverage, as an absolute rate difference, when both modes were selected. This measures the detector-threshold effect in this harness, not real decoy engagement or deception value. |
| Strategy reward | Mean of measured per-run closed-loop utility proxies; unavailable for other modes. |
| Simulated engagement rate | Completed runs with a seeded non-abandon reaction / completed runs, using the explicit reaction probabilities described above. |
| Mean synthetic interaction depth | Mean initial generated event count plus simulated follow-up events. This is not real session depth. |
| Median virtual session duration | Median virtual event timestamp span, including generated follow-up timestamps. It is not observed attacker dwell time. |
| Unique decoys accessed | Unavailable; synthetic source events do not identify decoy assets. |
| Average event processing time | Wall time for the per-event detector and local incident-correlation loop / events processed. Includes local SQLite correlation work; excludes temporary incident-store setup, model training/classification, synthetic scenario generation, and result persistence. |
| Experiment execution time | Measured wall time for the complete request, including model preparation, scenario generation, and persistence. Machine-dependent. |
| Resource use | Peak memory is unavailable; it is never estimated. |

Comparison differences are adaptive minus baseline. Percentage differences are
omitted when baseline is zero or unavailable. The standard API does not
calculate confidence intervals. A separate post-hoc scenario-cluster bootstrap
is available for the retained 150-run artifact; its ten scenario clusters are
too few for broad inference and the intervals describe only this synthetic
generator. Synthetic metrics
do not establish operational detection performance or real-world effectiveness.

## Reproduced data and model review (2026-11-27)

The data review used one published daily Cowrie export from the
[CyberLab Zenodo record](https://zenodo.org/records/3687527), DOI
`10.5281/zenodo.3687527`, under CC-BY-4.0. The selected archive's observed
SHA-256 is
`b681316de5ff58f8cae385fd4a2232d93ccdeb0b117ef58668195df5797d9c45`.
Processing yielded 7,465 sessions and 35,742 events. The archive has no trusted
behavior labels, so accuracy, precision, recall, and F1 are unavailable. The
synthetic-trained model's unlabeled category counts are distribution-review
outputs only. Raw compressed logs must remain outside the repository; the
processor does not export session keys, IPs, usernames, passwords, commands,
URLs, or payloads.

For a fresh local review, keep downloads and outputs under `%TEMP%`:

```powershell
$raw = Join-Path $env:TEMP 'cyberlab_2019-05-18.json.gz'
$summary = Join-Path $env:TEMP 'cyberlab-summary.json'
Invoke-WebRequest `
  -Uri 'https://zenodo.org/api/records/3687527/files/cyberlab_2019-05-18.json.gz/content' `
  -OutFile $raw
python experiments/process_cyberlab.py --input $raw --summary-output $summary
```

The independent synthetic holdout used 1,200 rows each for train, validation,
and test, with seeds 20261127, 20261128, and 20261129; selected models were
refit on 2,400 train-plus-validation rows. Random Forest, decision tree,
logistic regression, and the fixed evidence-rule baseline each measured 100%
accuracy and macro-F1, with 0% macro one-vs-rest FPR/FNR on the generated test
split. The rule baseline mirrors the generator's label thresholds, and the
other candidates see the same separable synthetic feature generator. These
perfect scores do not establish real-world model utility.

Because the original generator and its evidence-rule baseline produce perfectly
separable classes, an additional prespecified test uses a distinct episode-
based synthetic challenge. It chooses a latent dominant scenario before
sampling features, then adds overlapping secondary behaviors, broader/noisier
counts, missing aggregates, and benign low-activity examples. Fixed model
parameters selected on the original generator are tested without tuning on
the challenge rows. This remains synthetic-to-synthetic stress testing, not
real-world validation. Reproduce with:

```powershell
$challenge = Join-Path $env:TEMP ('profile-challenge-' + [guid]::NewGuid().ToString('N') + '.json')
python experiments/evaluate_profile_challenge.py --output $challenge `
  --samples-per-category 200 --train-seed 20301127 --test-seed 20301128
```

Reproduce model and paired runs with unique temporary output paths:

```powershell
$modelOut = Join-Path $env:TEMP ('profile-eval-' + [guid]::NewGuid().ToString('N') + '.json')
python experiments/evaluate_profile_models.py --output $modelOut `
  --samples-per-category 200 `
  --train-seed 20261127 --validation-seed 20261128 --test-seed 20261129

$pairedOut = Join-Path $env:TEMP ('paired-deception-' + [guid]::NewGuid().ToString('N') + '.json')
python experiments/run_deception_comparison.py --output $pairedOut `
  --seed 20261127 --repetitions 5
```

For paired run-level deltas and scenario-cluster bootstrap intervals, pass the
run artifact to `experiments/analyze_deception_comparison.py` with a new
temporary JSON output path.

The paired run covered 10 scenarios × 5 repetitions in baseline, adaptive,
and closed-loop modes: 50/50 runs completed in each mode. Baseline measured
75 TP, 0 FP, 150 FN (33.3% synthetic detection coverage); adaptive measured
90 TP, 0 FP, 135 FN (40.0%); closed loop measured 95 TP, 0 FP, 140 FN
(40.4%). Synthetic engagement estimates were 28%, 30%, and 20%, respectively;
these are seeded model outcomes, not observed attacker behavior. Corrected
per-event processing averages were 26.11 ms, 26.35 ms, and 23.86 ms on the
recording machine and include temporary per-run SQLite incident correlation.
FPR=0% is only the result against this generator's benign labels and rules; it
is not an operational false-alarm estimate. Exact run summaries are retained
in sanitized JSON artifacts referenced by the public snapshot.

## API

Run paired modes with a reproducible seed (maximum 10 scenarios, 10
repetitions, 3 modes, and 200 total mode-runs):

```powershell
$body = @{
  experiment_id = "demo-seed-2026"
  scenarios = @("reconnaissance", "multi_port_probing", "mixed_benign_suspicious_traffic")
  repetitions = 2
  seed = 2026
  modes = @("baseline", "adaptive", "closed_loop")
} | ConvertTo-Json -Depth 5
$run = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/experiments/run" `
  -ContentType "application/json" -Body $body
$id = $run.experiment_id
```

Inspect stored data and download reports:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/experiments?limit=20"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/experiments/$id"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/experiments/$id/results"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/experiments/$id/comparison"
Invoke-WebRequest "http://127.0.0.1:8000/api/v1/experiments/$id/report?format=json" -OutFile "$id.json"
Invoke-WebRequest "http://127.0.0.1:8000/api/v1/experiments/$id/report?format=csv" -OutFile "$id.csv"
Invoke-WebRequest "http://127.0.0.1:8000/api/v1/experiments/$id/report?format=markdown" -OutFile "$id.md"
```

The report endpoint supports `json`, `csv`, and `markdown`. All formats are
derived from stored experiment results. A caller may select only one mode;
comparison is then explicitly unavailable. Experiment IDs are unique and an
existing record is never overwritten.

## Storage and local execution

The experiment store is `data/experiments.sqlite3` by default. Configure
`HONEYPOT_EXPERIMENT_DB_PATH` before starting the API to select a different
SQLite file. Results are kept in a separate table/file from event, incident,
ledger, checkpoint, simulation, evaluation, profile, and strategy-sharing
stores. Correlator state during an experiment is temporary and isolated per
run. No database migration is needed.

Start the current backend as documented in the root README. In the dashboard,
open **Experiments**, select scenarios, repetitions, seed, and modes, then run.
The results view shows aggregate comparisons, scenario rows, adaptation
reasons, saved experiment IDs, and JSON/CSV/Markdown report links.

## Reproducible tests

Run tests from a source-only temporary copy, not from the working checkout.
The focused command below is run from that copy's root with its backend path on
`PYTHONPATH`:

```powershell
python -m pytest backend/tests/test_experiments.py -q
```

For example, create the focused copy from the repository root:

```powershell
$repoRoot = (Get-Location).Path
$tempRoot = Join-Path $env:TEMP ("honeypot-experiments-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $tempRoot "backend/tests") -Force | Out-Null
Copy-Item (Join-Path $repoRoot "backend/app") (Join-Path $tempRoot "backend/app") -Recurse
Copy-Item (Join-Path $repoRoot "backend/tests/test_experiments.py") (Join-Path $tempRoot "backend/tests/test_experiments.py")
$env:PYTHONPATH = "$(Join-Path $tempRoot 'backend');$tempRoot"
Push-Location $tempRoot
try { python -m pytest backend/tests/test_experiments.py -q }
finally { Pop-Location }
```

The root README describes the full-suite source copy, including the existing
local classifier artifact needed by older tests. Copy only that model artifact
and source/tests; exclude `data`, keys, backups, virtual environments, and
build output. Run `python -m pytest backend/tests -q` inside that copy.

Frontend checks from `frontend/`:

```powershell
npm test
npm run build
```

The tests use synthetic data and temporary paths. Do not copy real databases,
keys, backups, virtual environments, or build output into the source copy.

## Limitations

- Scenarios are generated synthetic event records, not traffic from a live
  attacker or real Zeek/Suricata/Cowrie sensors.
- Ground-truth labels are properties assigned by the scenario generator.
- The classifier was trained on a synthetic dataset; its category is a model
  output and not a verified label or calibrated threat score.
- The rule detector and local threshold adaptation are experimental harness
  components. Closed-loop reactions are seeded assumptions rather than
  calibrated attacker models. Approval/enforcement, network containment, and
  live honeypot configuration are not involved.
- Event capture is an in-memory processing measure; transport and sensor loss
  are not modeled. In this implementation all generated rows are handed to
  the local detector, so the rate is expected to be 100% absent an execution
  failure.
- The incident subsystem's own configured correlation rules determine
  incident results. A missing incident is not proof of benign behavior.
- Optional shared reader/admin bearer tokens protect the API when configured;
  no user accounts or organization identity exist. Keep the service on
  loopback or add suitable managed access control and TLS before deployment.
- Timing values vary by machine. Memory, confidence intervals, and real-world
  effectiveness are unavailable.
