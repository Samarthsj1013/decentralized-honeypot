# Interactive Browser Sandbox

The `deployment-v1` frontend includes a bounded security simulation lab for a
portfolio demonstration. The simulation runs in React state in the current
browser tab. It does not submit events to the deployed backend, write to a
database, persist in browser storage, open sockets, run commands, or target
real services. Refreshing the page resets its simulation state.

The Render process remains `app.public_demo:app`; its allowlist still serves
only `GET /healthz` and `GET /api/v1/public-demo`. The sandbox uses the
existing sanitized snapshot only for a separately labeled historical baseline.
It does not import the operational simulation package into Render.

## Scenarios and bounded inputs

Visitors can run:

- SSH authentication probing
- Repeated login failures
- Service reconnaissance
- Credential-decoy interaction
- Multi-stage synthetic activity
- Benign control activity
- Mixed synthetic activity

Each run accepts 1–24 interactions, low/medium/high virtual event spacing, a
static or behavior-conditioned strategy, and an optional unsigned 32-bit
reproducibility seed. Fixed seeds generate the same event sequence when the
scenario and settings match. Unseeded runs receive a random seed at run time.
All event types, service labels, sensor categories, and identifiers come from
fixed code allowlists; users cannot enter hosts, URLs, credentials, payloads,
commands, or arbitrary event text. Progress increments as the bounded event
loop creates each event. Timestamps are a simulated event clock; elapsed
milliseconds measure local browser execution time.

## Analysis rules

The current event sequence is the source for all displayed sandbox results:

- `repeated_authentication_failures`: at least three explicit synthetic
  authentication failure events.
- `service_reconnaissance_pattern`: at least three distinct synthetic service
  labels.
- `repeated_decoy_interaction`: at least two decoy interaction events.
- `cross_source_synthetic_correlation`: at least two sensor categories and
  two suspicious events in the same run.
- `unusual_interaction_frequency`: at least eight suspicious synthetic events
  over ten or fewer simulated seconds. Fully benign control sequences do not
  trigger alerts or recommendations.

An incident groups the alerts and their event references from the same run.
No alert means the selected rules did not fire; it is not proof that a
scenario is safe. The comparison's synthetic false-positive rate uses only the
generator's explicit benign labels. It is not an estimate of real operational
false positives.

The profile is a transparent heuristic over login attempts/failures, distinct
service labels, decoy interactions, and triggered incidents. Its displayed
score is:

```text
min(1, attempts × 0.04 + failures × 0.025 + distinct_services × 0.075
       + decoy_interactions × 0.04 + incidents × 0.12)
```

This is not the project's trained ML model, not a calibrated probability, and
not a validated risk score. The previously verified controlled Cowrie and
synthetic-model baseline remains in the separate **Previously verified
controlled local lab baseline** panel. It is never overwritten by browser
results.

## Decoys, recommendations, evaluation, and comparison

Static runs map every event to one disabled synthetic file-decoy template.
Adaptive runs select from fixed disabled file, credential, database, and
service decoy templates based on the event's observed action and service
label. A small sharing-specific validator checks schema version, synthetic
flags, disabled state, generated identifiers, category allowlists, and absence
of prohibited fields. This is not the operational coordinated bundle
validator and creates no deployable resource.

Recommendations are derived from observed login attempts, multiple service
labels, and credential-plus-database stages. The **Evaluate locally** action
replays the same scenario and seed in isolated in-memory data; it checks
recorded versus attempted interactions, local template validation, and that
the recommendation still has supporting evidence. Approve/reject updates only
this tab's local state. It does not call an API, activate a real adaptation
policy, or deploy a decoy.

Static/adaptive comparison runs 1–5 paired repetitions with identical seeds
per pair. It reports measured interactions, decoy-category coverage, alerts,
rule counts, scenario completion, and strategy changes. False-positive rate
and event counts are unavailable: this sandbox does not export event-level
prediction labels independently from its `suspicious` ground-truth labels, and
alert evidence is selected from suspicious events. Reporting zero would
therefore be structurally misleading. The benign control still verifies that
the configured rules emit no alerts or recommendations for that scenario. The paired model is
deterministic and adaptive output may be equal to or worse than static output.
The chart and metrics describe only this generator; they do not demonstrate
real-world effectiveness.

## Intelligence exchange

The browser-only exchange can publish an allowlisted alert rule identifier
from **Simulated Node A** to **Simulated Node B**. B records it as pending,
ignores a duplicate rule indicator, and supports explicit local approve/reject
review. The exchange has no network transport, signatures, ephemeral keys,
trusted publisher registry, durable audit, or consensus. It does not represent
the separate Ed25519-signed operational replication prototype and must not be
described as cryptographically verified or decentralized consensus.

## Run locally on Windows

Use two PowerShell terminals from the repository root. This public app uses a
new disposable snapshot database under `%TEMP%`; it does not use operational
stores or keys.

**Terminal 1 — isolated public snapshot API:**

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_ENV = 'development'
$env:HONEYPOT_CORS_ORIGINS = 'http://127.0.0.1:5173'
$env:HONEYPOT_DEMO_DB_PATH = (Join-Path $env:TEMP 'honeypot-interactive-demo\demo.sqlite3')
python -m uvicorn app.public_demo:app --app-dir backend --host 127.0.0.1 --port 8000
```

**Terminal 2 — Vite frontend:**

```powershell
Set-Location frontend
$env:VITE_PUBLIC_DEMO = 'true'
$env:VITE_API_BASE_URL = 'http://127.0.0.1:8000/api/v1'
npm.cmd ci
npm.cmd run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`. No login is used in the public-demo build.
The Vite app calls only the sanitized public snapshot API; sandbox simulation
remains in the tab. To run frontend checks, use `npm.cmd test` and
`npm.cmd run build` in `frontend`. To run backend tests, follow the
source-only temporary-copy procedure in [`TESTING.md`](TESTING.md).

## Deployment settings and release walk-through

Keep the production branch `deployment-v1`, Vercel root `frontend`, Render
entry point `app.public_demo:app`, and the existing `/api/:path*` rewrite to
the Render public service. Vercel Production variables remain
`VITE_PUBLIC_DEMO=true` and `VITE_API_BASE_URL=/api/v1`; do not put credentials
in `VITE_` variables. Keep Render's exact production CORS origin. Protect or
disable Vercel Preview deployments unless their exposure and branch behavior
have been reviewed.

Suggested visitor walkthrough:

1. Run **SSH authentication probing**, 8 interactions, medium intensity, seed
   `20261126`. Confirm the event progress reaches 100%, the result says 8/8,
   and the repeated-authentication rule has event evidence.
2. Filter the event table by event type and severity, then change sort order.
3. Inspect the heuristic profile and its contributing features. Confirm the
   assessment label does not claim ML inference.
4. Inspect generated disabled decoy templates. Evaluate the
   authentication-decoy recommendation and approve it in the sandbox. Confirm
   the label says sandbox only.
5. Run the paired static/adaptive comparison and review the repetition count,
   values, and synthetic-only note. Try the benign-control scenario to see
   that equal outcomes or a frequency-rule false positive are possible.
6. Select a generated alert and publish it from Node A to Node B. Publish it
   again to observe duplicate handling, then explicitly approve or reject the
   pending local indicator.
7. Run the benign-control scenario at each intensity and confirm it creates
   no alerts, incidents, or recommendations. Reset the sandbox and confirm its
   generated run state clears while the previously verified baseline remains
   unchanged.

## Reused logic and limitations

Scenario labels and behavior patterns follow the backend simulation and
deterministic adversary event generator. The browser implementation is a
separate small model and does not import the backend workflow, learned
classifier, event store, ledger, alert service, incident store, signed sharing
service, or operational bundle generator. No GAN, reinforcement learning,
network enforcement, real sensor monitoring, persistent sandbox, user account,
or consensus blockchain is implemented here. Do not describe these
synthetic results as evidence of detection effectiveness.
