# Implementation status

This is an academic software prototype. Status labels below describe code
paths and isolated demonstrations, not field deployment or security
certification. Updated 2026-11-28.

| Capability | Status | Evidence in repository | Boundary |
| --- | --- | --- | --- |
| FastAPI API and React/Vite dashboard | Implemented | `backend/app/main.py`, `backend/app/api/routes.py`, `frontend/src` | UI actions requiring administrator access need an appropriately secured API client; browser bundles must not contain admin tokens. |
| Interaction/event persistence | Implemented | `backend/app/honeypot/interaction.py`, `backend/app/events`, `backend/app/ledger` | Local SQLite durability; single-process in-memory event view. |
| Ledger and checkpoints | Implemented | `backend/app/ledger/service.py`, `checkpoint.py` | Hash chain detects edits relative to stored hashes; local signing key is not an external trust anchor. |
| Adaptive decoys and bundles | Implemented | `backend/app/adaptation`, `backend/app/honeypot` | Deterministic policy; generated values are synthetic and disabled. |
| Zeek / Suricata / Cowrie telemetry | Implemented as passive file adapters; controlled Cowrie run previously verified | `backend/app/telemetry/*`, `docs/FINAL_PLACEMENT_STATUS.md` | A local Docker Cowrie run produced 15 genuine Cowrie records that were ingested and rendered in telemetry/Cowrie panels. Zeek and Suricata fixtures are test inputs; no live Zeek or Suricata process was verified. |
| Incident correlation | Implemented | `backend/app/incidents` | Deterministic local rules; a rule match is an alert signal, not proof of compromise. |
| ML behavior profiles | Implemented with evidence-gated categories | `backend/app/profiling`, `backend/app/profiling/models_ml.py`, `backend/tests/test_profiling.py` | The synthetic classifier's category is retained only when its required observed aggregate features exist; otherwise it abstains to `unknown`. Synthetic holdout and unlabeled CyberLab distribution-review outputs are documented separately. Vote fractions are uncalibrated; no real-data accuracy metric is available. The local model artifact is ignored and must be generated from the documented synthetic trainer in a fresh checkout. |
| Offline adaptive experiments | Implemented with paired and closed-loop modes | `backend/app/experiments`, `backend/app/simulation/adversary.py`, `experiments/run_deception_comparison.py` | Ten seeded scenarios and 1–10 repetitions compare static, adaptive, and optional experiment-local closed-loop strategies. Labels/reactions are synthetic assumptions. Processing latency includes local per-event correlation, not setup or generation. |
| Signed strategy sharing | Implemented locally | `backend/app/strategy_sharing.py` | Explicit trust configuration; approval records state and does not enforce policy. |
| Threat-intelligence collection | Opt-in local prototype | `backend/app/network/replication.py`, `POST /v1/intelligence/observe` | Disabled by default; requires exact source/event mappings, severity, repeat threshold, and public IP; one signed snapshot per indicator/source/classification candidate. No automatic enforcement. |
| Peer registry and resilience | Experimental local node feature | `GET /v1/peers`, enable/disable, persistent node SQLite | Static configured identities only; status, last seen, failures, and sync attempts persist. No automatic discovery or multi-machine deployment verification. |
| Publisher key lifecycle | Explicit operator-managed | `/v1/publishers/{publisher_id}/keys/*`, node key registry | Replacement keys require fingerprint confirmation, explicit activation, and explicit revocation. Revocation is irreversible; no legal identity proof or automated key-distribution service. |
| Intelligence review | Local operator workflow | `/v1/intelligence/{record_id}/approve`, `/reject`, `/audit` | 30-day signed-created-at age limit, provenance links, duplicate/conflict relations, and a count-based confidence heuristic. Approval is not enforcement; confidence is not probability. |
| Organization replication | Experimental 3–5 node local process prototype | `backend/app/network/replication.py`, `backend/app/network/live_demo.py`, `backend/app/network/multi_node_demo.py`, `backend/tests/test_multi_node_demo.py` | Separate Uvicorn processes, test-only Ed25519 keys, and SQLite stores are exercised over localhost HTTP. Pending import, idempotency, tamper/untrusted-key rejection, downtime, and restart recovery are tested. No multi-machine deployment verification, consensus, quorum, or Byzantine fault tolerance. |
| Operational dashboard | Optional read-only node panel; public research snapshot is sanitized and static | `GET /v1/dashboard/summary`, `backend/app/public_demo_data.json`, `backend/app/public_demo.py`, `frontend/src/App.jsx` | The public snapshot now includes provenance-labeled dataset, synthetic holdout, and paired experiment aggregates. Its GET-only API does not expose operational endpoints. The interactive sandbox remains in-browser only; public metrics do not stream live sensor data. |
| Dashboard browser authentication | Implemented for the local UI | `backend/app/security.py`, `/api/v1/auth/session`, `frontend/src/App.jsx` | Runtime admin-token exchange into short-lived HttpOnly SameSite session with CSRF checks; process-local sessions/throttling, no user accounts, production requires Secure cookies/HTTPS. |
| Node dashboard credentials | Backend-side proxy | `/api/v1/network-node/dashboard` | Node read token is configured only in the backend; proxy has a fixed path, short timeout, no redirects, and response bound. |
| Sensor-to-profile and intelligence handoff | Opt-in local workflow | `/api/v1/telemetry/ingest`, `/api/v1/profiles/recompute`, configured `HONEYPOT_INTEL_COLLECTOR_*` | Accepted sensor events are durable before the configured bounded projection is forwarded to the node; profile recomputation groups by source IP. Collector is disabled by default and reports unavailable without discarding the persisted event. |
| Adaptive deception experiments | Synthetic paired experiments | `backend/app/experiments`, `/api/v1/experiments` | Seeded baseline/adaptive/closed-loop comparison measures detection, false-positive/negative, capture, simulated engagement/depth/virtual duration, and closed-loop reward. Real decoy access is unavailable because synthetic events do not identify decoy assets; results are not real-world effectiveness evidence. |
| Frontend/API shared-token auth | Implemented for local dashboard sessions | `backend/app/security.py`, `frontend/src/api.js` | Browser does not embed a reader/admin bearer token; it exchanges the operator-entered admin token for a short-lived HttpOnly session with CSRF protection. Shared-token access is not individual user identity. |
| Public placement deployment | Previously deployed to Vercel/Render; provider status not rechecked in this upgrade | `frontend/vercel.json`, `render.yaml`, `docs/CLOUD_DEPLOYMENT_GUIDE.md` | This work did not deploy or change provider configuration. Current provider health, auto-deploy state, and deployment revision are not verified here. The Render demo store is ephemeral; no HA or persistent production topology is claimed. |

## Claims to avoid

Do not describe the system as a decentralized blockchain, a trained real-world
intrusion detector, a self-learning live defense, a GAN, a reinforcement
learning policy, or proof of prevention. Only the separately documented
simulation mode uses a synthetic closed-loop reward policy. No actual Zeek,
Suricata, or Cowrie process is monitored by `/health`.

The public demo's historical successful-only Cowrie profile still displays its
original `authentication_probing` classifier output for audit, but its note
states that the current evidence gate abstains to `unknown` because no failed
logins were observed. The public summary labels data source and synthetic
ground-truth scope. Alerts/incidents populated panels were not visually
verified in the reported manual dashboard session.
