# Final Placement Readiness Status

**Latest verification:** 2026-11-26
**Verdict:** Demonstrable local academic prototype with successful manual
verification of login, telemetry, Cowrie activity, profiling, and recommendation
review. Limits remain around synthetic evaluation, optional panels, and
deployment scope.

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

The sidebar in `frontend/src/App.jsx` still reads **“Simulation mode / Synthetic
activity only”** while the dashboard also displays genuine external sensor
telemetry. This label is misleading for the mixed data view. It is recorded as
a UI wording issue; no frontend change was made in this closeout.

The repeatable Windows procedure, including restricted temporary token files
outside the repository and their cleanup, is in
[`FINAL_DEMO_GUIDE.md`](FINAL_DEMO_GUIDE.md).

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
