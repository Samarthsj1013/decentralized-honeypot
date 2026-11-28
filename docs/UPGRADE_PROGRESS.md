# DAHIN Upgrade Progress

## Release and working-tree preservation

- Initial research work began on local branch `dain-upgrade`, at the then
  current sandbox release commit. During the separately authorized placement
  release workflow, the working tree was switched to `deployment-v1` and the
  approved interactive-sandbox correction was committed and pushed as
  `f87ee43717d50daaaba28929fd6b333443760381`.
- A fresh remote fetch verified `origin/deployment-v1` at that same commit.
  `main` and `v1.0.0` remain at
  `ea5b214a5a13061984bfd5533c48f0207ffc6b6c`.
- No additional push or deployment is part of the ongoing research work.
- Pre-existing untracked backups, `test-event.json`, and the empty
  `docs/PLACEMENT_READINESS_AUDIT.md` are preserved and excluded from the
  research result allowlist.
- The isolated copy procedure preserves three required parser fixtures:
  `cowrie_events.jsonl`, `suricata_eve.jsonl`, and `zeek_conn.log`; it verifies
  their presence and byte lengths before pytest.

## Verified baseline

- Command: project `docs/TESTING.md` source-only-copy procedure, with runtime
  databases, key files, environment files, backups, caches, and build output
  excluded; legitimate test fixtures preserved and checked before pytest.
- Initial pre-upgrade result: `356 passed, 1 warning in 110.55s`
  (Starlette/httpx deprecation).
- Frontend: `npm.cmd test --prefix frontend`; `27 passed, 0 failed`.
- Public build: `VITE_PUBLIC_DEMO=true`, `VITE_API_BASE_URL=/api/v1`, output
  directed to a unique temporary directory; Vite transformed 35 modules and
  completed successfully.
- `git diff --check` passed before the upgrade branch was created.

## Findings and current resolution

1. Profile classes now require defining aggregate evidence; sparse and
   successful-only authentication observations abstain to `unknown`.
2. Public demo fixture `backend/app/public_demo_data.json` preserves the
   historical controlled Cowrie result (15 observations, 3 successful
   logins, zero failed auth/commands, category `authentication_probing`).
   Historical counters/class output are retained with a note that current
   evidence gating abstains; the previously measured rows were not rewritten.
3. Browser simulation's false-positive metric is explicitly unavailable
   because it lacks event-level predictions independent of its labels. The
   backend experiment detector has separate synthetic truth/predictions.
4. Existing offline experiment documentation explicitly identifies
   synthetic assumptions and unavailable metrics. No real-world effectiveness
   claim is currently justified.
5. A single public CyberLab Cowrie daily export was reviewed for license,
   provenance, fields, labels, bounds, and privacy. It has no trusted labels;
   no real-data accuracy metrics are reported.

## Work log

| Date | Milestone | Evidence / result | Remaining |
|---|---|---|---|
| 2026-11-27 | Preserve baseline | Branch `dain-upgrade` created from `deployment-v1`; `main` and tag SHA recorded; untracked user files retained. | Continue audit and implementation. |
| 2026-11-27 | Regression baseline | Isolated fixtures verified; backend 356 passed/1 warning; frontend 27 passed; public build passed. | Rerun full regression after changes. |
| 2026-11-27 | Classification correction | Evidence gates, sparse/success-only regression coverage, and historical snapshot caveat added. | Keep model output distinct from ground truth. |
| 2026-11-27 | Data/model review | Public CC-BY-4.0 CyberLab sample produced an unlabeled aggregate; separate seeded synthetic holdout compared RF/tree/logistic/evidence rules. | Real-data accuracy metrics unavailable; perfect synthetic scores reflect generator structure. |
| 2026-11-27 | Paired adaptive experiment | Ten scenarios × five repetitions × three modes completed 150/150; timer now excludes per-run database setup. | Synthetic assumptions only; machine-specific latency. |
| 2026-11-27 | Multi-node validation | Four-node localhost run passed with separate test keys/stores, signed transfer, duplicate/tamper/untrusted handling, downtime and recovery. | No relay, multi-machine deployment, or consensus. |
| 2026-11-27 | Public evidence and branding | Public snapshot schema 2 includes sanitized research summaries; DAHIN brand and operational sidebar wording updated. | Automated checks only; new panel/copy not manually browser-reviewed. |

## Latest current-tree verification (2026-11-27)

- Current branch: local `dain-upgrade` at `f87ee43717d50daaaba28929fd6b333443760381`.
  Local `deployment-v1` and `origin/deployment-v1` remain at that release
  commit. `main` and `v1.0.0` remain at
  `ea5b214a5a13061984bfd5533c48f0207ffc6b6c`. No additional commit or push
  was made for the research work.
- Focused source-copy command: `python -m pytest
  backend/tests/test_experiments.py backend/tests/test_public_demo.py -q`;
  **53 passed, 0 failed, 1 warning in 20.33s**.
- Final full backend source-copy run: **389 passed, 0 failed, 0 skipped, 1
  warning in 153.26s**. The warning is Starlette's deprecation notice about
  `httpx` with `starlette.testclient`. The copy preserved and byte-verified
  Cowrie JSONL (1,298 bytes), Suricata JSONL (2,145 bytes), and Zeek TSV
  `zeek_conn.log` (590 bytes) before pytest. It used a separate application
  temp directory and pytest `--basetemp`; the existing legacy model was copied
  only because its endpoint test requires it.
- Frontend: `npm.cmd test` reported **28 passed, 0 failed, 0 skipped**.
- Production frontend build with `VITE_PUBLIC_DEMO=true` and
  `VITE_API_BASE_URL=/api/v1` succeeded; Vite 6.4.5 transformed 35 modules and
  wrote output to a unique `%TEMP%` directory.
- The current `python -m app.network.multi_node_demo --nodes 4` returned
  `result=passed`: valid signed records imported pending on B/C, duplicates
  were recognized, tampering returned 400, an untrusted publisher returned
  403, offline state was detected, restart recovery succeeded, all key
  materials/database identities were unique. Direct local transfer measured
  1,154 ms and 783 ms on this machine.
- The paired synthetic experiment rerun completed all 150 runs. Corrected
  average processing measured 26.11 ms baseline, 26.35 ms adaptive, and
  23.86 ms closed-loop, including per-event local SQLite incident correlation.
- After that logged run, the complete backend suite was rerun on the current
  source snapshot and again passed **389 passed, 0 failed, 0 skipped, 1
  warning in 153.26s**. Frontend `npm.cmd test` passed **28/28** and the
  public-config Vite build succeeded (35 modules) into `%TEMP%`.
- The exact required fixture sizes were rechecked before this rerun.
  `git diff --check` and `git diff --cached --check` passed with only Git
  line-ending notices; the index remains empty.
- A compact scan of the production JS/CSS found no private-key PEM, JWT-like,
  GitHub/AWS/live-secret pattern, or operational admin/read/node token env
  names. The sanitized public snapshot contained none of the checked actor,
  event, source-IP, credential, private-key, database-ID, raw-event, payload,
  session-ID, or scenario-ID fields. This scan is pattern-based, not a
  general guarantee that a bundle is secret-free.
- `git ls-remote` could not connect to GitHub from this execution environment;
  the connected GitHub read tool did confirm the release commit SHA exists.
  No push or deployment was made for the research work.



## Production CORS hardening and final regression (2026-11-27)

- Security review found that the operational app's default loopback HTTP CORS
  origins were also accepted when `HONEYPOT_ENV=production`, unless the
  operator supplied a different list. The app now requires an explicit
  `HONEYPOT_CORS_ORIGINS` list in production and rejects every non-HTTPS origin;
  development loopback defaults remain. The session-origin check uses the same
  validation. Regression coverage includes missing origins, HTTP rejection,
  accepted HTTPS configuration, and an HTTP-origin login denied at the route.
- Focused isolated security tests: **22 passed, 0 failed, 1 warning in 10.51s**.
- Final full suite after the route regression: **391 passed, 0 failed, 0 skipped,
  1 warning in 191.96s**. The only warning is Starlette's `httpx`/
  `starlette.testclient` deprecation. Fixtures were verified before test
  execution. No real databases, signing keys, backups, or raw data were copied.
- Frontend remained unchanged after its verified **28/28** test run and Vite
  production build with `VITE_PUBLIC_DEMO=true` and
  `VITE_API_BASE_URL=/api/v1`.
- Current branch remains `dain-upgrade`; no staging, commit, push, or deployment
  was performed for this upgrade.

## Resumed final verification and outbound-token transport hardening (2026-11-28)

- Recovered on `dain-upgrade` at `f87ee43717d50daaaba28929fd6b333443760381`.
  `main` and `v1.0.0^{commit}` remain at
  `ea5b214a5a13061984bfd5533c48f0207ffc6b6c`. The switch to `deployment-v1`
  occurred for the separately authorized release request: `5a9ef19` added the
  14 approved sandbox files, and `f87ee43` followed it to correct false-positive
  metric reporting where the browser simulation had no independent predictions.
  The user explicitly authorized that commit and push after release checks;
  research work resumed on `dain-upgrade` at the pushed SHA. No research push or
  deployment has occurred.
- Security review found remote peer, node-dashboard, and optional collector
  endpoints could use cleartext HTTP while receiving backend-held bearer
  tokens. Validators now require HTTPS for remote hosts and permit HTTP only
  for loopback. Regression coverage includes URL safety, remote HTTP rejection,
  HTTPS acceptance, and loopback compatibility.
- Focused isolated security/replication tests: **52 passed, 1 warning** in
  50.53s. Full isolated backend suite after the fix: **399 passed, 0 failed,
  0 skipped, 1 warning** in 198.44s. The warning is the Starlette/httpx
  `TestClient` deprecation. Fixture sizes were verified before pytest.
- Frontend tests: **28 passed, 0 failed, 0 skipped** in 2.15s. Public-config
  build used `VITE_PUBLIC_DEMO=true`, `VITE_API_BASE_URL=/api/v1`, and an empty
  temporary Vite env directory. Vite 6.4.5 transformed 35 modules and
  succeeded in 2.59s. One attempted command used an unsupported `--envDir` CLI
  flag and failed; the successful programmatic Vite build followed. No app
  change was needed for that command error.
- Fresh four-node localhost demonstration returned `result=passed`: B and C
  accepted valid signed imports pending; duplicate delivery was idempotent;
  tampering returned 400; D without publisher trust returned 403; B was
  detected offline while A retained its local record; restart and re-sync
  succeeded. Keys and databases were distinct. Transfer times: B 1,030.480 ms,
  C 850.961 ms (machine-specific, local only).
- Fresh three-node and five-node demos also returned `result=passed` using
  separate generated keys and databases. Three nodes: transfer samples were B
  1,051.434 ms and C 938.740 ms; offline status was `unavailable`, and restart
  recovery stored a new record. Five nodes: B 1,122.538 ms and C 840.134 ms,
  tampering returned 400, untrusted publisher returned 403, offline status was
  `unavailable`, and restart recovery stored a new pending record. These are
  one-run localhost timings, not network SLO or multi-machine resilience
  measurements.
- Fresh paired experiment completed 150/150 runs (10 scenarios x 5
  repetitions x 3 modes). Detection coverage was 33.33% static, 40.00%
  adaptive, and 40.43% closed loop; generated-control FPR was 0%; simulated
  engagement was 28%, 30%, and 20%; mean synthetic interaction depth was 5.18,
  5.24, and 5.10. These are seeded generator outcomes, not real attacker
  effectiveness. Fresh synthetic holdout comparison measured accuracy and
  macro-F1 of 1.0 for RF, tree, logistic, and evidence-rule baseline; these
  scores describe agreement with generator labels only.
- Zenodo source metadata confirms CC BY 4.0 and documents Cowrie 1.6.0
  low-interaction collection through 2019-11-08, followed by Cowrie 2.0.2 with
  a high-interaction pool. The stored May 18, 2019 sample summary reports
  7,465 sessions and 35,742 events, including 2,023 login failures, 5,056
  successes, and 6 command attempts. It has no trusted labels. Quantitative
  feature-distance analysis remains unavailable: per-session rows were
  temporary and the fresh Zenodo download was blocked on 2026-11-28. No
  real-data accuracy is inferred.
- Docker context was `default`, but `docker info` could not open
  `npipe:////./pipe/docker_engine`; `zeek` and `suricata` were not on PATH. No
  live sensor was run in this continuation. Historical controlled Cowrie
  results from 2026-11-26 remain operator-reported evidence only.
- Automated browser access was unavailable. React SSR tests pass, but no fresh
  visual check of the research panel, alerts, or incidents was performed.
- Authentication/node-trust review confirmed shared admin/reader credentials,
  process-local 30-minute HttpOnly/Strict sessions with CSRF checks and login
  throttling, explicit publisher-key trust, key rotation/revocation,
  constant-time peer bearer comparison, signature/digest/expiry checks,
  bounded bodies, no redirects, and short network timeouts. This is not
  production IAM: no individual identities, MFA, persistent/distributed
  sessions, or distributed rate limiting. Remote outbound bearer destinations
  now require HTTPS; local loopback HTTP remains permitted.
- The active branch remains `dain-upgrade`; all ongoing changes are
  uncommitted. `main` and `v1.0.0` are unchanged. No push or deployment was
  made.

## Final verification closure (2026-11-28)

- A fresh source-only copy followed `docs/TESTING.md`. It excluded operational
  databases, key files, environment files, backups, caches, and build output;
  it preserved and verified the Cowrie JSONL (1,298 bytes), Suricata JSONL
  (2,145 bytes), and Zeek TSV `zeek_conn.log` (590 bytes) fixtures before
  pytest. The legacy synthetic classifier artifact was copied only into that
  temporary copy because an existing endpoint test requires it.
- Backend command in the isolated copy:
  `python -m pytest backend/tests -q --rootdir=<temporary-source-copy> --basetemp=<temporary-pytest-dir> -p no:cacheprovider`.
  Result: **404 passed, 0 failed, 0 skipped, 1 warning in 231.21s**. The only
  warning is Starlette's deprecation notice for `httpx` with
  `starlette.testclient`.
- Frontend `npm.cmd test`: **28 passed, 0 failed, 0 skipped** (3.16s).
  Public-config build with `VITE_PUBLIC_DEMO=true` and
  `VITE_API_BASE_URL=/api/v1` succeeded; Vite 6.4.5 transformed 35 modules
  (2.46s), writing output outside the repository. A bounded pattern scan of
  that bundle found no private-key header, bearer-token literal, or configured
  admin/read/ingestion/node token environment name. This is not a general
  secret-detection guarantee.
- Fresh 3-node and 5-node localhost demonstrations both returned
  `result=passed`, using separate temporary stores and unique test keys. In
  each, trusted imports were signature-valid and pending, repeated deliveries
  were duplicates, tampering returned 400, downtime was reported as
  unavailable, and restart recovery stored a new pending import. In the
  5-node run, two untrusted receivers rejected the publisher with 403.
  Sample transfer latencies ranged from about 796 to 1,150 ms; these are
  single-machine localhost observations, not network service targets.
- The fixed-parameter alternative-generator challenge used 1,200 training and
  1,200 challenge rows (200 per class; seeds 20301127 and 20301128). It
  measured RF accuracy/macro-F1 0.8600/0.8601, decision-tree 0.7525/0.7573,
  logistic 0.5358/0.5176, and evidence rules 0.4825/0.5165. This measures
  sensitivity to the authored synthetic generator shift only. The prior
  independent synthetic holdout remained 1.0 for all four candidates because
  labels are structurally tied to generated feature thresholds; exact
  same-label vector overlaps across split pairs were 40–41. CyberLab has no
  trusted behavioral labels, and quantitative per-feature shift distances
  remain unavailable because the retained data is aggregate-only and a fresh
  Zenodo download was blocked.
- Paired scenario-cluster bootstrap on the 150-run static/adaptive/closed-loop
  artifact (10 scenarios × 5 repetitions × 3 modes; 20,000 draws) found
  adaptive-minus-closed-loop simulated engagement of -10.0 percentage points
  with 95% interval [-28.0, +4.0]. The interval includes zero. The policy
  selected `neutral_response` on 43/50 closed-loop runs; this and seeded
  reaction assumptions explain the point estimate but establish no real
  attacker-engagement effect.
- The current-source read-only app is available on loopback at
  `http://127.0.0.1:8001` with a temporary SQLite file; Vite is at
  `http://127.0.0.1:5174` with an empty temporary env directory. Health and
  snapshot returned 200; schema 3 included four holdout candidates, four
  challenge candidates, two alerts, one incident, and one profile. Exact
  local CORS was accepted. Event, ingestion, evaluation, and ledger paths and
  query-string variants returned 404; an unapproved origin returned 403.
  Existing services occupied ports 8000/5173 and served a schema-2 snapshot;
  they were not stopped or changed.
- Browser automation host reported unavailable. Chrome was not navigated.
  React SSR tests verified populated public sections, but an owner still needs
  to visually inspect the current schema-3 research panel, alerts, incidents,
  profiles, recommendation state, and responsive layout at the local URL.
- The Docker Engine named pipe was previously unavailable and Zeek/Suricata
  executables were absent from `PATH`; this continuation did not claim fresh
  live sensor verification. The 2026-11-26 Cowrie result remains historical
  operator-verified evidence. A final check showed Docker context `default`;
  `docker info` exited 1 because `npipe:////./pipe/docker_engine` was absent
  in this execution environment (the Docker CLI also could not read the user's
  Docker config). `zeek` and `suricata` remain unavailable on `PATH`. No Docker
  configuration was changed.

## Final automated browser and release closure (2026-11-29)

- Recovered the isolated browser result from the preceding execution: a real
  Chrome/Playwright run against the temporary read-only API and Vite frontend
  passed. Evidence files (`browser-result.json`, desktop screenshot, mobile
  screenshot) remain under the temporary `dahin-browser-run-*` directory and
  are not repository artifacts.
- Browser coverage checked all 10 navigation entries, seven scenario modes,
  bounded interaction input (including leading-zero normalization), benign
  no-alert/no-recommendation behavior, same-seed reproducibility, telemetry
  filtering and ordering, evaluation and explicit approval, strategy
  comparison, simulated intelligence duplicate/review, and sandbox reset with
  the 15-event historical baseline preserved.
- At viewport widths 1440, 768, and 390 pixels, document and body widths
  matched the viewport. The browser recorded no console errors, page errors,
  failed requests, or external requests. It made two GET requests to the
  configured `/api/v1/public-demo` snapshot endpoint (React development
  StrictMode); no sandbox action contacted an operational API route.
- The research view displayed the CyberLab provenance/label limitation,
  synthetic holdout and challenge, paired experiment and correctly directed
  confidence interval, historical-versus-corrected classification caveat,
  and measured 3/4/5-node localhost replication table. The dashboard shows
  alerts, incidents, profiles, and recommendation states from the sanitized
  snapshot. Browser checks validated rendered content; they do not establish
  operational efficacy.
- Final backend suite was rerun from a fresh source-only copy using the
  `docs/TESTING.md` procedure. Cowrie JSONL (1,298 bytes), Suricata JSONL
  (2,145 bytes), and Zeek TSV `zeek_conn.log` (590 bytes) were verified in the
  copy first. Result: **404 passed, 0 failed, 0 skipped, 1 warning in 193.99s**.
  The warning is Starlette's `httpx`/`TestClient` deprecation notice.
- The first complete frontend run exposed one stale source assertion expecting
  the phrase “historical model output”; the rendered UI intentionally says
  “Historical output, not the corrected current decision.” The assertion was
  aligned with the actual classification caveat; no UI behavior or validation
  was weakened. Rerun: **28 passed, 0 failed, 0 skipped**.
- Public-config production build (`VITE_PUBLIC_DEMO=true`,
  `VITE_API_BASE_URL=/api/v1`) succeeded with Vite 6.4.5 (35 modules), output
  under `%TEMP%`. A bounded asset scan found no configured token environment
  names, private-key headers, or JWT-shaped literals.
- Isolated public backend: `/healthz` and `/api/v1/public-demo` returned 200;
  event, profile, ledger, auth, OpenAPI, ingestion, and public-demo mutation
  paths returned 404. The configured Vite origin received the matching CORS
  header; `https://untrusted.example` received 403. This verifies the public
  app instance, not the separate operational deployment.
- Corrected presentation assertions now match the tested UI: DAHIN branding,
  “Research Evidence” navigation, right-minus-left experiment contrast,
  confidence interval interpretation, historical classification caveat, and
  measured backend replication results distinct from the browser's simulated
  intelligence exchange.
- Current working branch remains `dain-upgrade`; no commit, push, merge, or
  deployment was made. `main` and `v1.0.0` remain untouched. The temporary
  browser evidence, build, and pytest stores are outside the repository.
