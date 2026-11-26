# Implementation status

This is an academic software prototype. Status labels below describe code
paths, not field deployment or security certification.

| Capability | Status | Evidence in repository | Boundary |
| --- | --- | --- | --- |
| FastAPI API and React/Vite dashboard | Implemented | `backend/app/main.py`, `backend/app/api/routes.py`, `frontend/src` | UI actions requiring administrator access need an appropriately secured API client; browser bundles must not contain admin tokens. |
| Interaction/event persistence | Implemented | `backend/app/honeypot/interaction.py`, `backend/app/events`, `backend/app/ledger` | Local SQLite durability; single-process in-memory event view. |
| Ledger and checkpoints | Implemented | `backend/app/ledger/service.py`, `checkpoint.py` | Hash chain detects edits relative to stored hashes; local signing key is not an external trust anchor. |
| Adaptive decoys and bundles | Implemented | `backend/app/adaptation`, `backend/app/honeypot` | Deterministic policy; generated values are synthetic and disabled. |
| Zeek / Suricata / Cowrie telemetry | Implemented as passive file adapters | `backend/app/telemetry/*` | Requires operator-provided log files, API URL, sensor ID and ingestion token. It does not install or probe sensors. |
| Incident correlation | Implemented | `backend/app/incidents` | Deterministic local rules; a rule match is an alert signal, not proof of compromise. |
| ML behavior profiles | Implemented; local artifact generated for this checkout | `backend/app/profiling`, `backend/app/profiling/models_ml.py` | The local `attacker_profile_models.joblib` is generated from synthetic data with 80 examples per category and seed 2026; it is ignored by Git and must be generated in a fresh checkout. It reports version `attacker-profile-synthetic-v1`, feature schema 1, 30 features, and artifact SHA-256 `9e091be00a2e95a8b8492152b43822a235dc7580e95e67bfe826f9143436cfe3`. Scores are uncalibrated and not validated on real attacks. A separate legacy actor endpoint uses `experiments/results/behavior_model.joblib`. |
| Offline adaptive experiments | Implemented | `backend/app/experiments`, `backend/app/simulation/adversary.py` | Seeded simulation; all labels/reactions are scenario assumptions. |
| Signed strategy sharing | Implemented locally | `backend/app/strategy_sharing.py` | Explicit trust configuration; approval records state and does not enforce policy. |
| Threat-intelligence collection | Opt-in local prototype | `backend/app/network/replication.py`, `POST /v1/intelligence/observe` | Disabled by default; requires exact source/event mappings, severity, repeat threshold, and public IP; one signed snapshot per indicator/source/classification candidate. No automatic enforcement. |
| Peer registry and resilience | Experimental local node feature | `GET /v1/peers`, enable/disable, persistent node SQLite | Static configured identities only; status, last seen, failures, and sync attempts persist. No automatic discovery or multi-machine deployment verification. |
| Publisher key lifecycle | Explicit operator-managed | `/v1/publishers/{publisher_id}/keys/*`, node key registry | Replacement keys require fingerprint confirmation, explicit activation, and explicit revocation. Revocation is irreversible; no legal identity proof or automated key-distribution service. |
| Intelligence review | Local operator workflow | `/v1/intelligence/{record_id}/approve`, `/reject`, `/audit` | 30-day signed-created-at age limit, provenance links, duplicate/conflict relations, and a count-based confidence heuristic. Approval is not enforcement; confidence is not probability. |
| Organization replication | Experimental live-process prototype | `backend/app/network/replication.py`, `backend/app/network/live_demo.py`, `backend/tests/test_network_replication.py` | Separate Uvicorn processes, stores, and Ed25519 keys are exercised over localhost HTTP; no multi-machine deployment verification, consensus, quorum, or Byzantine fault tolerance. |
| Operational dashboard | Optional read-only node panel | `GET /v1/dashboard/summary`, `frontend/src/App.jsx` | Displays real configured-node health, peers, intelligence state, and sync failures through the backend proxy. Adaptive comparison is the existing synthetic experiment dashboard. |
| Dashboard browser authentication | Implemented for the local UI | `backend/app/security.py`, `/api/v1/auth/session`, `frontend/src/App.jsx` | Runtime admin-token exchange into short-lived HttpOnly SameSite session with CSRF checks; process-local sessions/throttling, no user accounts, production requires Secure cookies/HTTPS. |
| Node dashboard credentials | Backend-side proxy | `/api/v1/network-node/dashboard` | Node read token is configured only in the backend; proxy has a fixed path, short timeout, no redirects, and response bound. |
| Sensor-to-profile and intelligence handoff | Opt-in local workflow | `/api/v1/telemetry/ingest`, `/api/v1/profiles/recompute`, configured `HONEYPOT_INTEL_COLLECTOR_*` | Accepted sensor events are durable before the configured bounded projection is forwarded to the node; profile recomputation groups by source IP. Collector is disabled by default and reports unavailable without discarding the persisted event. |
| Adaptive deception experiments | Synthetic paired experiments | `backend/app/experiments`, `/api/v1/experiments` | Seeded baseline/adaptive/closed-loop comparison measures detection, false-positive/negative, capture, simulated engagement/depth/virtual duration, and closed-loop reward. Real decoy access is unavailable because synthetic events do not identify decoy assets; results are not real-world effectiveness evidence. |
| Frontend/API shared-token auth | Implemented for local dashboard sessions | `backend/app/security.py`, `frontend/src/api.js` | Browser does not embed a reader/admin bearer token; it exchanges the operator-entered admin token for a short-lived HttpOnly session with CSRF protection. Shared-token access is not individual user identity. |
| Production deployment | Not verified | `deploy/cowrie/compose.yaml` is a controlled local sensor configuration | No complete production deployment topology, secrets service, HA, or public exposure validation. |

## Claims to avoid

Do not describe the system as a decentralized blockchain, a trained real-world
intrusion detector, a self-learning live defense, a GAN, a reinforcement
learning policy, or proof of prevention. Only the separately documented
simulation mode uses a synthetic closed-loop reward policy. No actual Zeek,
Suricata, or Cowrie process is monitored by `/health`.
