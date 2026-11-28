# Final Placement Readiness Status

**Latest code and automated browser verification:** 2026-11-29
**Latest manual sensor/dashboard verification:** 2026-11-26
**Verdict:** GO for the isolated recruiter-facing public demonstration and an
exploratory academic prototype with explicit limitations; NO-GO for an
operational production security platform. The current research dashboard was
automatically exercised in Chrome at desktop, tablet, and mobile widths.

## Final automated verification (2026-11-29)

- Fresh isolated backend suite: **404 passed, 0 failed, 0 skipped, 1 warning**
  in 193.99 seconds. The warning is Starlette's deprecation notice for using
  `httpx` with `starlette.testclient`. Fixture copies were verified before
  pytest; databases and keys were temporary and separate.
- Frontend suite: **28 passed, 0 failed, 0 skipped**. Public-config production
  build succeeded using Vite 6.4.5 (35 modules), with output under `%TEMP%`.
  A bounded bundle scan found no configured token variable names,
  private-key headers, or JWT-shaped strings.
- Chrome/Playwright exercised the populated read-only snapshot and sandbox:
  all 10 nav entries; seven scenarios; leading-zero input normalization;
  benign control; same-seed reproducibility; telemetry filtering/sorting;
  recommendation evaluation/approval; strategy comparison; simulated
  intelligence duplicate/review; reset isolation; and preservation of the
  15-event historical baseline.
- At widths 1440, 768, and 390 pixels, page/body widths matched the viewport.
  The run recorded zero console errors, page errors, failed requests, or
  external requests. Only two GETs to `/api/v1/public-demo` were observed;
  sandbox actions did not contact operational endpoints.
- The rendered research view includes the corrected right-minus-left
  comparison direction and interval, synthetic-data caveats, historical versus
  corrected classification, and 3/4/5-node signed localhost measurements.
  Temporary screenshots and machine-readable evidence are outside the repo.
- Isolated public API `/healthz` and `/api/v1/public-demo` returned 200;
  operational event/profile/ledger/auth/OpenAPI/ingestion routes and public
  mutation paths returned 404. Exact local CORS was allowed; an untrusted
  origin was rejected with 403.

Current browser evidence establishes rendering and local interaction behavior,
not human visual judgment on every device/browser or real-world security
effectiveness. Earlier statements below that browser automation was unavailable
refer to the 2026-11-28 checkpoint and are superseded by this section.

## Latest code verification (2026-11-28)

The resumed source-only regression run passed **399 tests, 0 failures, 0
skipped, 1 Starlette/httpx deprecation warning**. The frontend passed **28
tests**, and a public-config Vite build transformed 35 modules successfully.
Remote peer/dashboard/collector bearer URLs now require HTTPS unless the target
is loopback; focused regression tests cover both. These checks do not replace a
new browser review of the research panel, live Zeek/Suricata sensors, or
populated alert and incident panels. Detailed commands and fixture checks are in
[`UPGRADE_PROGRESS.md`](UPGRADE_PROGRESS.md).

## Manual browser verification (2026-11-26)

The project operator reported completing this verification from the original
project directory. These values are recorded from that run; this documentation
update did not rerun the services or tests.

- Administrator login, logout, and re-login succeeded.
- Cowrie started in Docker. Three controlled SSH sessions generated **15
  genuine Cowrie records**; ingestion reported **15 accepted, 0 errors, and 0
  duplicates**.
- The React telemetry and Cowrie activity panels rendered. The dashboard
  showed **3 successful emulated logins**, **6 session events**, **0 failed
  logins**, and **0 command attempts**.
- Profile recomputation produced one profile with **15 observations**:
  **Authentication Probing**, mean anomaly index **0.438**, cluster **4**,
  model `attacker-profile-synthetic-v1`.
- One adaptive deception recommendation was created. Local evaluation passed
  with **8/8 interactions**, **10 synthetic decoys**, and **678.5 ms** duration;
  explicit recommendation approval succeeded.

The successful Cowrie logins are emulated outcomes inside the honeypot. They do
not indicate access to a real host. Recommendation approval is a workflow state
and did not deploy decoys or enforce a policy.

The operator visually verified the telemetry and Cowrie activity panels.
Populated alerts and incidents panels were **not** visually verified. The
optional network-node dashboard was unconfigured. The observed zero failed
logins and zero command attempts are not evidence that alert or incident
rendering was tested.

The operational sidebar wording was corrected on 2026-11-27 to **“Offline
experiments / Synthetic scenarios; sensor feed separate”**, distinguishing
generated scenarios from external telemetry. Frontend source and SSR checks
cover the copy, but this wording change has not received a separate manual
browser review.

The public snapshot was updated to schema version 3 with sanitized research
aggregates: a labeled-source CyberLab sample review, the original synthetic
holdout, an alternate-generator synthetic challenge, and paired strategy
effects with scenario-cluster intervals. The historical
successful-only Cowrie profile output remains visible for audit, with a note
that the current evidence gate would abstain to `unknown` because no failed
logins were present. These new summary panels are covered by automated
backend and React server-render tests; the previously reported manual browser
session did not inspect them.

The repeatable Windows procedure, including restricted temporary token files
outside the repository and their cleanup, is in
[`FINAL_DEMO_GUIDE.md`](FINAL_DEMO_GUIDE.md).

## Final closeout work (2026-11-28)

The original classifier's 100% synthetic holdout result was investigated.
Distinct generator seeds do not prevent all exact feature collisions: the
train/validation/test splits had 40–41 pairwise shared vectors, always with the
same label. The original generator also emits near-disjoint category signals
and the evidence-rule baseline mirrors those signals. These are likely
optimism causes; duplicate vectors alone do not account for perfect scores.

A separate 1,200-row alternate-generator synthetic challenge was added with
latent dominant-scenario labels, mixed secondary behavior, missing aggregates,
and count noise. Measured accuracy/macro-F1 were RF 0.8600/0.8601, decision
tree 0.7525/0.7573, logistic regression 0.5358/0.5176, and fixed rules
0.4825/0.5165. RF exceeds rules in this authored synthetic setting only; no
real-world classifier value is established. The public snapshot and research
panel now show this result.

The retained paired experiment was reanalyzed with a 20,000-draw
scenario-cluster bootstrap. Adaptive-minus-closed-loop engagement was -10.0
percentage points (95% interval -28.0 to +4.0), so the lower 20% closed-loop
sample rate versus 30% adaptive is inconclusive. Detection coverage contrasts
are summarized in [`EXPERIMENTAL_RESULTS.md`](EXPERIMENTAL_RESULTS.md). This
analysis uses ten synthetic scenario clusters and does not estimate actual
attacker engagement.

Per-session CyberLab features could not be recovered from the temp directory;
the retained file is aggregate-only. A new source download attempt failed with
a connection error, so numeric feature-distance analysis remains unavailable.
Docker Engine remains inaccessible from this execution environment, and
Zeek/Suricata binaries are absent; no new live sensor verification is claimed.
Browser automation is unavailable. The current local public-demo research
panel still needs owner visual review; steps are listed in the final report.

## Earlier isolated verification (2026-11-25)

The results below are retained as the earlier source-copy audit and are separate
from the 15-event original-checkout browser run above.

## Verified in this run

- Profile model generated using the repository trainer: 480 synthetic rows,
  six categories, 80 per category, seed 2026. Runtime health reported the
  profile model available. The artifact is local and Git-ignored; a new
  checkout must generate it again. Version: `attacker-profile-synthetic-v1`,
  schema 1, 30 features, SHA-256
  `9e091be00a2e95a8b8492152b43822a235dc7580e95e67bfe826f9143436cfe3`.
- Docker CLI, Compose, and Docker Engine were checked. The normal sandbox
  could not access the Windows Docker named pipe; a separately approved local
  execution check reached Docker context `desktop-linux`, Engine 29.9.3.
- Pinned Cowrie image `cowrie/cowrie:3.1.5` started under the existing
  loopback/internal-network Compose configuration. Because the host port was
  not actually published by this Docker Desktop configuration, the bounded
  SSH test client ran inside Cowrie and connected only to its own loopback.
  It generated three sessions per invocation, used throwaway credentials,
  requested no shell, and did not print credentials.
- 49 genuine Cowrie JSON log records were ingested through the existing CLI
  and authenticated API into the isolated application run. Replaying the log
  with a fresh cursor produced 49 confirmed duplicates and no extra ledger
  entries. The final ledger had 50 entries: 49 Cowrie events and one
  deliberately synthetic Suricata alert used to demonstrate correlation.
  Ledger verification returned `valid=true`.
- The API reported healthy and the profile model available. The isolated run
  produced 3 incidents, one alert (from the synthetic Suricata event), 2
  source-IP profiles, and 3 pending recommendations. Cowrie summaries were
  available at their API route. No claim is made that the synthetic Suricata
  event came from a sensor.
- Authentication check: invalid login 401; valid session login 200; cookie
  HttpOnly; authenticated read 200; CSRF-protected recompute 200; logout 200;
  read after logout 401. Missing ingestion authentication returned 401,
  malformed JSON 400, invalid schema 422. These were isolated temporary
  tokens and stores.
- Focused backend tests: **57 passed, 1 warning in 55.17s**.
- Complete isolated backend suite: **319 passed, 1 warning in 93.22s**.
  Warning: Starlette deprecation notice for `httpx` with
  `starlette.testclient`.
- Frontend: **9 tests passed, 0 failed**. Production build succeeded with
  Vite 6.4.5 (31 modules). Dev server root returned HTTP 200.
- Dashboard route integration is covered by a new isolated API test. Browser
  automation was unavailable; visual rendering of all dashboard panels was
  not observed and remains unverified.

## Limitations and outstanding work

- Cowrie host port 2222 was not reachable even though Compose specified a
  loopback host mapping; `docker inspect` showed no published host port. The
  verified demonstration worked wholly inside the Cowrie container. Do not
  relax the internal network or bind to a public interface to address this.
- Cowrie's default honeypot behavior recorded the generated logins as
  emulated successes. The activity demonstrates sensor output and ingestion,
  not failed authentication or compromise.
- The configured model was trained on synthetic data and is uncalibrated; no
  real-world accuracy is reported. The current checkout's generated artifact
  is ignored and is not a portable checked-in model.
- One Suricata alert in the demonstration was synthetic. No live Suricata or
  Zeek sensor was run in this verification.
- The 2026-11-25 isolated audit did not visually check the browser. The
  2026-11-26 manual run verified telemetry and Cowrie activity rendering, but
  did not visually verify populated alerts or incidents. The node dashboard
  remains optional and returns a configuration error until its backend-only
  URL and token are set.
- Alerts and UI sessions have process-local aspects. There are no individual
  user accounts, production identity provider, consensus protocol, or
  multi-machine reliability demonstration. Intelligence approval does not
  enforce or block indicators.

## Changes made during this continuation

- `deploy/cowrie/compose.yaml`: corrected the official Cowrie image reference
  from `cowrie/cowrie:v3.1.5` to `cowrie/cowrie:3.1.5` after the former tag
  failed to pull.
- `deploy/cowrie/local_ssh_probe.py`: added the bounded, credential-safe
  container-loopback SSH probe used because the configured host port was not
  published.
- `backend/tests/test_dashboard_telemetry_integration.py`: added an isolated
  end-to-end telemetry/dashboard API integration test using temporary stores.
- `docs/IMPLEMENTATION_STATUS.md`: recorded the generated profile model's
  current local configuration and synthetic-data boundary.
- `docs/FINAL_DEMO_GUIDE.md`: added reproducible PowerShell setup, sensor,
  ingestion, verification, and shutdown instructions.
- `docs/FINAL_PLACEMENT_STATUS.md`: this evidence and limitation report.
- Earlier pre-existing uncommitted changes in the Windows replication demo,
  its regression test, architecture/security docs, and placement audit were
  preserved. See the repository's current `git status --short` for all files.

## Interview explanation

**Cybersecurity:** “I built a passive pipeline that ingests genuine local
Cowrie JSON, removes sensitive fields, deduplicates records, persists them in
a local hash-chain ledger, and correlates selected metadata into reviewable
incidents. The alert is a triage signal, not proof of compromise, and nothing
automatically blocks traffic.”

**Software engineering:** “I integrated a file adapter with authenticated
FastAPI ingestion and isolated SQLite stores, exercised retry/idempotence and
ledger integrity, trained a versioned synthetic profile model, and added
temporary-database integration tests. The app has signed local node exchange,
but not distributed consensus or production identity management.”

## Reproduction

Use [Final Demo Guide](FINAL_DEMO_GUIDE.md), [Testing](TESTING.md), and
[Demo Guide](DEMO_GUIDE.md). The exact suite commands and temporary-copy
procedure are in `TESTING.md`; results above are from the recorded isolated
run, not a new run of this document.

## Final DAHIN closeout (2026-11-28)

The newest isolated regression after the alternate-generator challenge and
paired-interval additions is **404 backend tests passed, 0 failed, 0 skipped,
1 Starlette/httpx deprecation warning**; frontend **28/28** and the
public-config build passed. Current-source 3-node and 5-node localhost
demonstrations passed integrity, trust, duplicate, downtime, and recovery
checks. The current-source public app is available at
`http://127.0.0.1:5174` for owner visual review; browser automation was
unavailable, so that visual review is still required. See
[`UPGRADE_PROGRESS.md`](UPGRADE_PROGRESS.md) for exact evidence and remaining
limits.
