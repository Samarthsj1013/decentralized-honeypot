# DAHIN Release Readiness

**Current verdict: GO for the isolated recruiter-facing public demonstration; NO-GO for an operational security platform.** The current `dain-upgrade` source passed isolated backend/frontend regression, a public-config production build, and automated Chrome verification on 2026-11-29. This is not authorization to commit, push, merge, or deploy; none was performed. `main` and `v1.0.0` remain at `ea5b214a5a13061984bfd5533c48f0207ffc6b6c`.

## Verification gates

| Gate | Status | Evidence and limits |
|---|---|---|
| Preserve release history | Pass locally | Branch is `dain-upgrade`; `main` and `v1.0.0` remain at the release SHA above. No history-changing operation was performed. |
| Regression | Pass 2026-11-29 | Fresh isolated backend: **404 passed, 0 failed, 0 skipped, 1 Starlette/httpx deprecation warning**. Frontend: **28 passed, 0 failed, 0 skipped**. Required Cowrie/Suricata/Zeek fixtures were verified byte-for-byte before pytest. |
| Production build and bundle scan | Pass | Vite 6.4.5, `VITE_PUBLIC_DEMO=true`, `VITE_API_BASE_URL=/api/v1`, 35 modules; output under `%TEMP%`. Bounded scan found no configured token names, private-key headers, or JWT-shaped literals. |
| Automated browser | Pass | Chrome/Playwright checked populated snapshot and sandbox workflows. At 1440/768/390 px there was no horizontal overflow. Zero console/page errors, failed or external requests. The only requests were two GETs to `/api/v1/public-demo`; sandbox actions made no operational API calls. |
| Public routes and CORS | Pass for isolated app | `/healthz` and `/api/v1/public-demo` returned 200. Operational read/auth/OpenAPI/ingestion paths and public-demo mutations returned 404. Configured Vite origin was allowed; untrusted origin returned 403. |
| Research presentation | Pass | DAHIN branding, Research Evidence navigation, correct right-minus-left contrast/interval, historical-versus-current classification caveat, and measured 3/4/5-node results rendered. Backend replication is distinguished from browser simulation. |
| Research validity | Partial by design | CyberLab sample is aggregate-only and unlabeled; no real-data accuracy or quantitative feature-distance result. Synthetic challenge/experiment outcomes do not establish field effectiveness. |
| Sensors/cloud | Partial | Historical controlled Cowrie run is documented; no live Docker/Zeek/Suricata run in this final cycle. Render/Vercel deployment status was not queried or changed. |

The browser run checked all 10 navigation entries, seven scenarios, leading-zero
normalization, benign controls, seeded repeatability, telemetry filtering and
sorting, local evaluation and explicit approval, strategy comparison, simulated
intelligence review, reset isolation, and preservation of the 15-event
historical baseline. Temporary screenshots and JSON evidence are outside the
repository; browser checks are not real-world effectiveness evidence.

## Separate readiness assessments

- **Recruiter-facing public demonstration: GO** for the isolated, accurately
  labeled read-only snapshot and browser-local sandbox. Branch promotion and
  public hosting still require owner authorization.
- **Academic research prototype: GO with limits** as exploratory work. The
  authored synthetic challenge measured RF macro-F1 0.860 versus fixed rules
  0.516. CyberLab has no trusted labels; these are not real-world metrics.
- **Operational security platform: NO-GO.** Individual IAM/MFA, distributed
  sessions/rate limiting, consensus, labeled field validation, and current
  live Zeek/Suricata verification are absent. Do not expose operational APIs.

## Intended release allowlist

Recommendation only; nothing is staged. Exclude unlisted files, especially
backups, `test-event.json`, the empty `docs/PLACEMENT_READINESS_AUDIT.md`,
databases, keys, model binaries, environment files, raw telemetry, temporary
logs, and build output.

```text
.gitignore
README.md
backend/app/api/routes.py
backend/app/experiments/analysis.py
backend/app/experiments/real_cowrie.py
backend/app/experiments/service.py
backend/app/experiments/storage.py
backend/app/main.py
backend/app/network/multi_node_demo.py
backend/app/network/replication.py
backend/app/profiling/challenge.py
backend/app/profiling/evaluation.py
backend/app/profiling/service.py
backend/app/public_demo.py
backend/app/public_demo_data.json
backend/app/security.py
backend/tests/test_deception_analysis.py
backend/tests/test_experiments.py
backend/tests/test_multi_node_demo.py
backend/tests/test_network_replication.py
backend/tests/test_profiling.py
backend/tests/test_profiling_challenge.py
backend/tests/test_profiling_evaluation.py
backend/tests/test_public_demo.py
backend/tests/test_real_cowrie_dataset.py
backend/tests/test_security.py
docs/DEMO_GUIDE.md
docs/EXPERIMENTAL_EVALUATION.md
docs/EXPERIMENTAL_RESULTS.md
docs/FINAL_PLACEMENT_STATUS.md
docs/IMPLEMENTATION_STATUS.md
docs/RELEASE_READINESS.md
docs/SECURITY.md
docs/TESTING.md
docs/UPGRADE_PLAN.md
docs/UPGRADE_PROGRESS.md
experiments/analyze_deception_comparison.py
experiments/evaluate_profile_challenge.py
experiments/evaluate_profile_models.py
experiments/process_cyberlab.py
experiments/results/cyberlab_2019-05-18_summary.json
experiments/results/paired_deception_20261127_retimed.json
experiments/results/profile_model_evaluation_20261127.json
experiments/run_deception_comparison.py
frontend/index.html
frontend/src/App.jsx
frontend/src/public-demo.test.js
frontend/src/styles.css
```

Suggested commit: `research: close DAHIN placement verification`. After owner
approval, open a reviewed PR from `dain-upgrade` to `main`; preserve
`v1.0.0`. Update `deployment-v1` only after review/merge using a normal
fast-forward or reviewed merge. Provider auto-deploy status was not observable.

## Deployment and rollback

The public service entry point is `app.public_demo:app`, separate from the
operational API. Before any approved deployment, check Render's entry point,
Vercel's `/api/:path*` rewrite and exact CORS origin, and confirm no privileged
tokens enter frontend build configuration. Verify `/healthz` and
`/api/v1/public-demo` after deploy; do not publish Cowrie/SSH.

For an approved rollback, use provider dashboards to redeploy the last known
good `deployment-v1` commit `f87ee43717d50daaaba28929fd6b333443760381`, then
verify those two routes. Do not rewrite Git history, move `v1.0.0`, or alter
operational data. No deployment or rollback occurred in this verification.

## Remaining limitations

- The browser sandbox uses deterministic synthetic heuristics; its intelligence
  exchange is not cryptographic replication.
- Local signed-node experiments have no consensus or Byzantine fault tolerance.
- No trusted real-world classifier labels or numeric CyberLab feature-distance
  result are available. The paired synthetic engagement interval includes zero.
- Alerts, incidents, profiles, and recommendations in the recruiter snapshot
  are sanitized demonstration data, not a live sensor feed. Approval does not
  deploy decoys or enforce policy.
- Operational identity, MFA, distributed availability, and live Zeek/Suricata
  verification remain absent.
