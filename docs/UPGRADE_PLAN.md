# DAHIN Upgrade Plan

This plan converts the master upgrade request into verifiable milestones. It
is a working plan; status is evidence-based and does not imply production
effectiveness.

| ID | Objective and verification evidence | Status | Dependencies / next action |
|---|---|---|---|
| P0 | Preserve the interactive release; record branch and refs; correct the isolated source-copy procedure; capture current regressions. Evidence: Git refs/status, fixture checks, test outputs. | Complete | Release commit `f87ee43` is on local `deployment-v1` and `origin/deployment-v1`; GitHub confirms the commit exists. Current `dain-upgrade` remains local; main and peeled tag remain `ea5b214`. The fixture-preserving copy verified all three required fixture sizes before the full run. |
| P1 | Audit telemetry, profiling, ML, adaptation, experiments, replication, security, public demo and cloud paths. Evidence: code-path review and regression tests. | Implemented with runtime limits | Backend auth/session, ingestion, CORS, public route isolation, key trust, peer identity, replay, timeouts and bearer transport were reviewed. Remote peer/dashboard/collector bearer endpoints now require HTTPS; loopback HTTP remains allowed. Live sensor/browser constraints are recorded in the final status. |
| P2 | Explain and correct classification from evidence, including successful-only, failed-auth bursts, benign, mixed and sparse observations. Preserve the historical snapshot. | Implemented | Evidence-gated classes and regression tests cover successful-only, minimum failed-auth and feature evidence thresholds; historical category is labeled as original output and current abstention. |
| P3 | Verify public dataset provenance, license, labels, fields, size and privacy; process safely without claiming real-data metrics. | Implemented for one sample | Zenodo record 3687527 confirms Cowrie experiment context; one-day sample measured 7,465 sessions/35,742 events. No trusted labels. Descriptive shift analysis is recorded; numerical feature-distance analysis is unavailable because the per-session export is absent and Zenodo fetch failed in this environment. |
| P4 | Add leakage-aware model evaluation and unknown handling; compare justified candidates; publish measured results and limitations. | Implemented for synthetic labels | Separate seeded train/validation/test sets and evidence-rule baseline are reported. Perfect generator scores do not establish utility; no labeled real-data test exists. |
| P5 | Use bounded paired experiments and honest metric semantics. | Implemented for synthetic scenarios | Ten scenarios × five repetitions × three modes; false-positive metric is available only from the backend detector against explicit synthetic labels. Browser sandbox FPR remains unavailable without independent predictions. |
| P6 | Verify signed intelligence across 3–5 isolated nodes including integrity, replay, trust, interruption and recovery. | Implemented as localhost prototype | `multi_node_demo.py` and parameterized tests cover 3, 4, and 5 processes, separate keys/stores, pending imports, retries, rejection, downtime and recovery. No consensus or multi-machine claim. |
| P7 | Audit sensor parsing, normalization, deduplication, ordering, privacy and suspicious-evidence correlation. | Partial | Fixture suites and historical controlled Cowrie run are documented. Zeek/Suricata executables and accessible Docker Engine were unavailable here; fresh live runs were not performed. |
| P8 | Brand public/project-facing materials DAHIN without renaming compatible packages or APIs. | Implemented | React title/brand and operational sidebar wording updated; automated source/SSR checks cover copy. New wording has not received a separate manual browser review. |
| P9 | Show verified provenance/measurements while preserving browser-local simulation and public API isolation. | Complete; manual visual review pending | Public snapshot schema 3 adds a sanitized alternate-generator challenge result and paired intervals. Source has only `/healthz` and `/api/v1/public-demo`; middleware permits only GET, rejects query strings and other routes, and sandbox tests assert it does not call network APIs. |
| P10 | Recheck authentication, ingestion boundaries, CORS, keys, revocation, public route allowlist, sandbox isolation and bundle contents. Evidence: route/auth tests, explicit trust config, source and build scan. | Implemented and regression tested | Includes remote bearer URL TLS enforcement, session and route tests, explicit key trust/revocation, public route allowlist and bundle scans. No individual IAM, MFA, distributed sessions, consensus, or external penetration test. |
| P11 | Run full isolated backend and frontend suites, data/model/experiment/replication/security tests, build and diff checks. | Complete on 2026-11-28 | Fresh source-only suite: 404 passed, 0 failed, 0 skipped, 1 Starlette/httpx warning; frontend: 28 passed; public-config build succeeded; final `git diff --check` passed. |
| P12 | Document architecture, threat model, data provenance, methods, results, limits and reproduction commands. | Implemented for verified scope | Experimental shift assessment now distinguishes observed event mix from synthetic class labels and states why quantitative feature-distance is unavailable. Remaining runtime verification limits are explicit. |
| P13 | Verify deployment branch/config/environment/resource compatibility and rollback plan; no further push or deployment. | Partial / no release | Main and v1.0.0 remain unchanged. Current provider health/auto-deploy status and fresh visual dashboard check are unavailable; research changes remain uncommitted and no push/deployment is authorized in this upgrade task. |
| P14 | Investigate perfect synthetic holdout scores and compare models on an alternate-generator, overlapping challenge. | Complete; synthetic-only | Fixed model parameters were tested on 1,200 challenge rows; RF macro-F1 0.860 vs fixed rules 0.516. This is authored synthetic evidence only. Original splits had 40–41 same-label exact feature collisions per pair. |
| P15 | Reanalyze paired deception outcomes with scenario-level uncertainty and explain closed-loop engagement. | Complete; synthetic-only | Run-level paired bootstrap over ten scenario clusters; engagement contrast adaptive minus closed loop -10.0 pp, 95% interval -28.0 to +4.0. Does not establish a systematic effect. |

## Explicit completion boundaries

- A model output is not confirmed malicious intent.
- Synthetic labels and controlled lab activity are reported separately from
  independently collected telemetry.
- Signed replication and hash chains do not imply distributed consensus.
- A ready-to-review release is not a deployed release. Push and deployment
  remain gated on explicit owner approval.
- The alternate-generator challenge is synthetic, and missing aggregates are
  represented as zero; it cannot establish real-world classifier value.
