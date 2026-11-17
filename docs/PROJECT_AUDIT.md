# Repository audit

## Scope and evidence

This audit describes the checked-out Python/FastAPI backend, React/Vite
dashboard, tests, simulator scripts, model artifacts, Docker Compose sensor
configuration, and documentation. It is based on source inspection; a passing
test suite does not establish real-world detection or prevention effectiveness.

## Architecture

- `backend/app/api/routes.py` exposes the FastAPI API and wires application
  services.
- Honeypot interactions use an in-memory event view plus the append-only local
  SQLite hash-chain ledger. Decoys and coordinated bundles use a separate
  SQLite registry. Adaptation history, evaluations, simulations, profiles,
  incidents, experiments, and shared strategy imports each have separate
  persistence modules.
- Normalized telemetry is appended to the ledger, restored into the event
  store at startup, projected into bounded alerts/live updates, and correlated
  into local incidents.
- Zeek, Suricata, and Cowrie adapters parse local log files and forward
  normalized events to one configured ingestion endpoint. Cowrie also has an
  optional loopback-bound Docker Compose honeypot.
- Profile inference uses explicitly synthetic training data. The online
  policy is rule-based; the closed-loop experiment mode is a deterministic
  simulation with explicit synthetic assumptions.
- Strategy packages are sanitized, canonicalized, digested and Ed25519
  signed. The replication module simulates participants in-process with
  separate stores; it is not a peer network or consensus system.
- `frontend/src` is a dashboard client. A Vite reader token is shipped to the
  browser and is therefore visible to its user.

## Implemented status

| Area | Present implementation | Not established |
| --- | --- | --- |
| API access | Optional shared reader/admin bearer tokens and separate telemetry token | User accounts, sessions, per-user audit, rate limiting |
| Event integrity | Local SHA-256 chain and signed Ed25519 checkpoints | Independent replication, consensus, immutable remote backup |
| Telemetry | Bounded generic schema and file adapters for Zeek, Suricata, Cowrie | Proof that external sensors are running or lossless live collection |
| Alerts/incidents | Deterministic rules and SQLite correlation | Calibrated threat probabilities or verified compromise |
| Behavior profiles | Synthetic-trained classifier, anomaly baseline and clusters over selected aggregates | Real-world labels, calibrated confidence, demonstrated detection performance |
| Adaptation | Deterministic policy and validated synthetic decoy bundles | GAN, reinforcement learning in the live policy, automatic enforcement |
| Experiments | Offline synthetic baseline/adaptive/closed-loop scenarios | Real attacker outcomes or operational effectiveness |
| Strategy sharing | Signed records, explicit local trust, pending evaluation and approval | Authenticated organization identity, remote transport, revocation service, consensus |
| Dashboard | API-backed telemetry, incidents, profiles and experiments | Browser-safe administrative identity when shared-token auth is enabled |
| Operations | Loopback-oriented local commands and optional constrained Cowrie Compose service | Production deployment, secrets service, HA, or public exposure validation |

## Prioritized remediation

1. Before non-local use, put the API behind TLS and a managed identity/access
   layer; do not expose the development-open configuration.
2. Add rate limits, request quotas, operational monitoring, and retention limits
   before accepting untrusted or high-volume sensors.
3. Protect the ledger checkpoint private key and local SQLite files with
   operating-system permissions and independent backups. Import-time service
   construction currently initializes the ledger store and checkpoint key.
4. Treat all `joblib` model artifacts as trusted executable input. Load only
   operator-controlled files; do not accept an artifact upload endpoint.
5. Add real sensor deployment/health monitoring and test event-loss behavior
   before describing the platform as a live production defense network.
6. For distributed use, add authenticated peer identities, key rotation and
   revocation, replay/freshness policy, remote transport, failure recovery,
   and a defined replication/consensus protocol.

See [Security](SECURITY.md), [Architecture](ARCHITECTURE.md),
[Implementation status](IMPLEMENTATION_STATUS.md), [Testing](TESTING.md), and
[Demo guide](DEMO_GUIDE.md) for operational boundaries and reproducible
commands.
