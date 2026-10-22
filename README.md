# Decentralized AI Self-Evolving Honeypot Network

An experimental cybersecurity research prototype for adaptive honeypots,
behavioral threat analysis, and decentralized threat intelligence.

## Project Status

Prototype: the current behavior-conditioned policy is deterministic and
rule-based. It does not implement a GAN, reinforcement learning, or live
network enforcement. Scenario evaluations use synthetic interactions.

## Research Goals

- Build a controlled honeypot environment.
- Analyze decoy interaction events.
- Develop and evaluate a conditional generative decoy model.
- Compare learned adaptation policies with the deterministic baseline.
- Investigate privacy-preserving, authenticated cross-organization sharing.
- Evaluate deception outcomes with controlled attacker-facing measures.

## Safety

Testing is restricted to authorized, isolated environments and synthetic data.

## Local setup

From the repository root, install backend dependencies and start FastAPI:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
python -m uvicorn app.main:app --reload --app-dir backend
```

The API documentation is at `http://127.0.0.1:8000/docs`. To run the Vite
dashboard in a second PowerShell window:

```powershell
Set-Location frontend
npm install
npm run dev
```

Frontend checks are `npm test` and `npm run build` from `frontend`. Backend
tests initialize SQLite and the ledger checkpoint key through application
imports. Run them using the source-only temporary-copy instructions below so
test stores and keys remain isolated from local application data.

## Synthetic decoy bundles

Behavior-conditioned strategy changes create version 1 bundles from a single
canonical synthetic entity. The related identity, database record, file, and
API representation share the same synthetic employee and project identifiers.
Bundle relationships are validated before persistence. The bundle and its
legacy decoy-list projections are written in one SQLite transaction. Values
are marked as disabled or test-only and are not valid credentials.

After recording an interaction, generate a bundle with:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/decoys/decoy-credential-001/interactions" `
  -ContentType "application/json" `
  -Body '{"actor_id":"demo-actor-001","action":"attempt_login"}'
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/bundles/generate/demo-actor-001?scenario_id=demo"
```

The response includes a consistency result and projected decoy IDs. Retrieve
the persisted bundle and validate it without changing state:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/bundles/bundle-<id>"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/bundles/bundle-<id>/validation"
```

A bundle is structured as follows (identifiers and values here are examples):

```json
{
  "bundle_id": "bundle-example",
  "schema_version": 1,
  "actor_id": "demo-actor-001",
  "selected_strategy": "credential_decoy",
  "strategy_reason": "Synthetic login behavior observed",
  "fingerprint_version": 1,
  "canonical_entities": [{
    "entity_id": "bundle-example-entity",
    "employee_id": "EMP-TEST001",
    "synthetic_name": "Synthetic Employee TEST001",
    "department": "Research Sandbox",
    "project_code": "LAB-TEST001",
    "service_identity": "synthetic_service_test001",
    "synthetic_only": true
  }],
  "identities": [{
    "asset_id": "bundle-example-identity",
    "entity_id": "bundle-example-entity",
    "employee_id": "EMP-TEST001",
    "synthetic_name": "Synthetic Employee TEST001",
    "department": "Research Sandbox",
    "project_code": "LAB-TEST001",
    "service_identity": "synthetic_service_test001",
    "authentication_state": "DISABLED_SYNTHETIC"
  }],
  "api_resources": [{
    "asset_id": "bundle-example-api",
    "entity_id": "bundle-example-entity",
    "method": "GET",
    "resource_path": "/synthetic/api/v1/entities/test001",
    "representation": {
      "employee_id": "EMP-TEST001",
      "department": "Research Sandbox",
      "project_code": "LAB-TEST001",
      "service_identity": "synthetic_service_test001"
    }
  }],
  "relationships": [
    {"source_asset_id": "bundle-example-entity", "relationship": "has_identity", "target_asset_id": "bundle-example-identity", "relationship_key": "bundle-example-identity-link"},
    {"source_asset_id": "bundle-example-entity", "relationship": "exposed_as_api_resource", "target_asset_id": "bundle-example-api", "relationship_key": "bundle-example-api-link"}
  ],
  "synthetic_only": true
}
```

The actual API response also includes generated timestamps, strategy rationale,
fingerprint version, and the remaining modeled entity fields. The independent
validator reports schema, identifier, reference, and cross-asset consistency
issues; successful validation means internal synthetic-data consistency only.

## Behavioral fingerprint contract

The existing operational `BehavioralFingerprint` remains fingerprint v1 and
continues to drive adaptation and bundle generation. A separate adapter in
`backend/app/intelligence/fingerprint_schema.py` exposes the contract
`decentralized_honeypot.behavioral_fingerprint`, schema version 1. The adapter
does not change existing strategy thresholds or fingerprint fields. It
validates a bounded, typed view and rejects unknown schema versions instead of
reinterpreting them. Legacy v1 API records without `schema_name` and
`schema_version` are accepted only when `fingerprint_version` is 1.

Stable v1 operational features are:

| Feature | Type and meaning |
| --- | --- |
| `event_count` | Non-negative interaction count, max 100,000. |
| `unique_decoys_accessed`, `unique_actions` | Non-negative counts bounded by `event_count`. |
| `action_sequence` | Ordered observed actions; length equals `event_count`. |
| `action_frequencies` | Counts by observed action; absent/empty legacy maps derive from the verified action sequence. |
| `decoy_types_accessed` | Unique observed category labels. |
| `decoy_type_frequencies` | Observed category counts; an empty legacy map stays unavailable instead of being inferred from unique categories. |
| `credential_probing`, `database_probing`, `file_probing`, `repeated_access` | Validated boolean indicators derived by the existing extractor. |
| `first_seen`, `last_seen` | Internal timestamps; optional in validated representations. |
| `timing_reliable` | True only when timestamps are comparable and the span is positive. |
| `elapsed_seconds`, `interactions_per_minute` | Finite numeric timing features only when reliable; otherwise null. |
| `risk_score`, `risk_level` | Existing 0–100 deterministic heuristic score and low/medium/high category. |
| `reasons`, `assessment_type` | Internal explanatory text and the fixed heuristic-baseline label. |

The compatibility adapter preserves fingerprint v1 semantics. Missing action
counts are derived from `action_sequence`; missing decoy-category counts remain
unknown. Unsupported versions, inconsistent counts, contradictory probing
flags, invalid ranges, non-finite values, and invalid timing combinations are
rejected. Comparable timestamps with an invalid order are also rejected.

### Canonical shareable export

`GET /api/v1/intelligence/fingerprints/{actor_id}/export` returns an explicit
allowlist: schema name/version, event and unique counts, fixed action and decoy
category count maps, probing/repeated indicators, timing reliability and
coarsened timing bands, and the existing heuristic risk category. Unknown
categories are trimmed, lowercased, then aggregated into a fixed `other`
bucket. The export excludes actor IDs, sequences, raw timestamps, event/decoy
IDs, reasons, payloads, and paths. A legacy missing decoy-frequency map is
zero-filled only with `decoy_type_frequencies_available: false`.

Canonical JSON uses UTF-8-safe compact JSON, lexically sorted object keys,
explicit null values, and standard JSON booleans/numbers. It contains no export
timestamp. The accompanying SHA-256 is computed over those canonical UTF-8
bytes and is an integrity/content identifier only; it is not anonymization.

Example internal v1 fingerprint (normally returned by the existing fingerprint
endpoint):

```json
{
  "fingerprint_version": 1,
  "actor_id": "synthetic-actor-001",
  "event_count": 1,
  "unique_decoys_accessed": 1,
  "unique_actions": 1,
  "action_sequence": ["read"],
  "action_frequencies": {"read": 1},
  "decoy_types_accessed": ["file"],
  "decoy_type_frequencies": {"file": 1},
  "credential_probing": false,
  "database_probing": false,
  "file_probing": true,
  "repeated_access": false,
  "elapsed_seconds": null,
  "interactions_per_minute": null,
  "timing_reliable": false,
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-01-01T00:00:00Z",
  "risk_score": 0,
  "risk_level": "low",
  "reasons": ["No additional heuristic risk indicators observed"],
  "assessment_type": "heuristic_baseline"
}
```

Its shareable export contains the same aggregate counts and booleans, but no
`actor_id`, timestamps, sequence, or reason text. Its vector has the fixed
26-value order below; this example vector is for the one-event `read` case
above:

```json
{
  "schema_name": "decentralized_honeypot.behavioral_fingerprint",
  "schema_version": 1,
  "event_count": 1,
  "unique_decoys_accessed": 1,
  "unique_actions": 1,
  "action_frequencies": {
    "view": 0, "read": 1, "attempt_login": 0, "query": 0, "other": 0
  },
  "decoy_type_frequencies": {
    "file": 1, "credential": 0, "database_record": 0, "other": 0
  },
  "decoy_type_frequencies_available": true,
  "credential_probing": false,
  "database_probing": false,
  "file_probing": true,
  "repeated_access": false,
  "timing_reliable": false,
  "elapsed_time_band": null,
  "interaction_rate_band": null,
  "risk_level": "low"
}
```

```json
{
  "schema_name": "decentralized_honeypot.behavioral_vector",
  "schema_version": 1,
  "fingerprint_schema_name": "decentralized_honeypot.behavioral_fingerprint",
  "fingerprint_schema_version": 1,
  "feature_order": [
    "event_count", "unique_decoys_accessed", "unique_actions",
    "action_frequency.view", "action_frequency.read",
    "action_frequency.attempt_login", "action_frequency.query",
    "action_frequency.other", "decoy_type_frequencies_available",
    "decoy_frequency.file", "decoy_frequency.credential",
    "decoy_frequency.database_record", "decoy_frequency.other",
    "credential_probing", "database_probing", "file_probing",
    "repeated_access", "timing_reliable", "elapsed_seconds.value",
    "elapsed_seconds.missing", "interactions_per_minute.value",
    "interactions_per_minute.missing", "risk_score", "risk_level.low",
    "risk_level.medium", "risk_level.high"
  ],
  "values": [1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0]
}
```

Every vector value is a finite float. Boolean indicators use 0/1; risk level is
one-hot; action and decoy frequencies use fixed category dimensions with an
`other` bucket. Null timing uses value 0 paired with a missing-indicator value
of 1. Missing legacy decoy frequencies use zero counts and an explicit
availability value of 0. The vector is an input adapter for future
scikit-learn-compatible models, not a trained model and not evidence of better
detection accuracy.

### Fingerprint endpoints

```text
GET  /api/v1/intelligence/fingerprints/schema
POST /api/v1/intelligence/fingerprints/validate
GET  /api/v1/intelligence/fingerprints/{actor_id}/export
GET  /api/v1/intelligence/fingerprints/{actor_id}/vector
```

The schema endpoint returns feature definitions, fixed vector order, missing
and unknown-category rules, and the compatibility policy. The validation body
is an operational fingerprint object; a legacy object from
`GET /api/v1/intelligence/fingerprints/{actor_id}` is accepted as v1 without
adding schema metadata. Successful validation returns only validity and schema
metadata; malformed input returns HTTP 422 with sanitized field errors. The
export and vector endpoints return derived representations and do not persist
or alter history, bundles, events, or the ledger. Actor-specific paths follow
existing API conventions; this application currently has no authentication
layer, so deployment access controls remain the operator's responsibility.

Removing direct identifiers does not make an export anonymous. Rare action
combinations, event counts, risk categories, and coarse timing buckets can
still be linkable with outside information. Share only under an appropriate
data-sharing agreement and review each organization's privacy requirements.

## Technology Stack

- Python
- FastAPI
- scikit-learn
- Deterministic behavior-conditioned policy
- React and Vite
- Reinforcement learning (future research)
- Permissioned blockchain (planned)

## Signed strategy sharing (Phase 4)

Strategy-sharing record schema is `decentralized_honeypot.strategy_share`,
version 1. Version 1 is strict: unknown fields and unsupported versions are
rejected; later incompatible formats require a new schema version. Records
contain a simulated organization ID, strategy, the existing allowlisted
fingerprint aggregate and its digest, a sanitized bundle-template projection
(asset/relationship categories only) and its digest, a canonical record
digest (`SHA-256`), key ID, timestamp, and Ed25519 signature. They do not include actor,
event, scenario, decoy, or bundle IDs; raw events; free-text rationale; asset
content; credentials; or private keys. A digest provides integrity checking,
not anonymity or confidentiality.

The signature uses the domain prefix
`decentralized-honeypot:strategy-sharing:v1\0`; this is separate from ledger
checkpoint signing. Configure a dedicated Ed25519 PKCS#8 private key path with
`HONEYPOT_STRATEGY_SHARING_PRIVATE_KEY_PATH`, its simulated issuer with
`HONEYPOT_STRATEGY_SHARING_ORGANIZATION_ID`, and its key ID with
`HONEYPOT_STRATEGY_SHARING_KEY_ID`. The verifier trust map is explicitly
configured in `HONEYPOT_STRATEGY_SHARING_TRUSTED_KEYS` as JSON mapping key IDs
to `organization_id` and PEM `public_key`. Imported records cannot add keys to
this map, and the checkpoint key is never used as an organization identity.
Do not configure a signing key for an organization unless its public key is
also provisioned in the explicit trust map. The organization name is an
operator mapping from key ID to a simulated label; it is not proof of a real
publisher identity. There is no automated key rotation or revocation protocol.
Update the trust configuration and restart the process to change trust.
Pending and evaluated records are rechecked against the current configured key
at activation; already active approval records are not automatically revoked.

API workflow:

```text
POST /api/v1/strategy-sharing/exports/{actor_id}
POST /api/v1/strategy-sharing/imports
GET  /api/v1/strategy-sharing/imports/{record_id}
POST /api/v1/strategy-sharing/imports/{record_id}/evaluate
POST /api/v1/strategy-sharing/imports/{record_id}/activate
```

After configuring the dedicated signer and trust map, PowerShell can export,
import, evaluate, and activate a package as follows (the actor identifier is
used only to select local source data; it is not included in the returned
record):

```powershell
$record = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/exports/demo-actor-001"
$imported = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/imports" `
  -ContentType "application/json" `
  -Body ($record | ConvertTo-Json -Depth 20)
$recordId = $imported.record_id
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/imports/$recordId/evaluate"
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/imports/$recordId/activate"
```

Export creates only the sanitized signed record. Import verifies strict schema,
fingerprint and template digests, template consistency, trusted organization
key, and signature before storing it as `pending`. Evaluation runs the
existing five-scenario evaluation service with isolated temporary SQLite
databases and records its actual summary. It passes only if all requested
scenario runs complete and the imported strategy appears in measured strategy
selections. A failed or incomplete evaluation cannot be activated. Activation
is a separate audited approval state; it does not replace or override the
existing local deterministic strategy-selection policy.

Duplicate imports of the same record ID are rejected by the local primary key.
Replay detection is local to this SQLite store; there is no shared replay
registry or freshness window across installations. The API has no
authentication or authorization, so these routes must not be exposed to an
untrusted network. The export route takes an actor ID in its URL, which may be
present in HTTP access logs even though it is excluded from the signed record.
Evaluation responses expose aggregate metrics only; detailed per-run records
remain in the local sharing database.

This implementation uses simulated organization IDs for repeatable local
testing. There is no authenticated organization identity, remote transport,
or consensus layer. The registry is a local SQLite record store, not a
decentralized blockchain. Since the API has no authentication, deployment
access controls remain the operator's responsibility.

### In-process organization replication demonstration

`backend/app/strategy_replication.py` provides `SimulatedOrganizationNode` for
an in-process two-node demonstration. Each node has a separate SQLite path and
its own Ed25519 private key. Operators explicitly provision each peer's public
key in the receiver's trust map. The sender exports the signed record as a
JSON-compatible dictionary; the receiver verifies it through the existing
strategy-sharing service, stores it as pending, evaluates it locally, and
requires a separate approval call. A node without the sender key and a
modified transfer payload are rejected. Duplicate record IDs return HTTP 409
without replacing the first import. Private keys are held by their source node
and are not part of the transfer payload.

This is a local simulation of independent participants. It does not provide
remote transport, authenticated organization identity, consensus, shared
replay detection, high availability, or Byzantine fault tolerance. The
demonstration is reproducible with the test-only generated keys and temporary
SQLite stores in this command (run it from a source-only temporary copy as in
the test instructions below):

```powershell
python -m pytest -q backend/tests/test_strategy_sharing.py::test_two_organization_replication_and_untrusted_third_node
```

Run focused sharing tests from a temporary source copy. The backend initializes
SQLite stores and a local checkpoint key when its modules are imported, so
running these tests directly in the working checkout may touch that checkout's
local development data. The following PowerShell commands copy only source and
the focused test; all SQLite files and test keys are then created under the
temporary copy:

```powershell
$repoRoot = (Get-Location).Path
$tempRoot = Join-Path $env:TEMP ("honeypot-sharing-test-" + [guid]::NewGuid().ToString("N"))
$pytestTemp = Join-Path $env:TEMP ("honeypot-sharing-pytest-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path (Join-Path $tempRoot "backend\app") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tempRoot "backend\tests") -Force | Out-Null
New-Item -ItemType Directory -Path $pytestTemp -Force | Out-Null
Copy-Item -Path (Join-Path $repoRoot "backend\app\*") -Destination (Join-Path $tempRoot "backend\app") -Recurse -Force
Copy-Item (Join-Path $repoRoot "backend\tests\test_strategy_sharing.py") (Join-Path $tempRoot "backend\tests") -Force
$env:PYTHONPATH = "$(Join-Path $tempRoot 'backend');$tempRoot"
Push-Location $tempRoot
try {
  & (Join-Path $repoRoot ".venv\Scripts\python.exe") -m pytest -q --rootdir=$tempRoot --basetemp=$pytestTemp -p no:cacheprovider backend/tests/test_strategy_sharing.py
} finally {
  Pop-Location
}
```

For the complete backend suite, make the same kind of temporary copy containing
`backend/app`, `backend/tests`, `backend/requirements.txt`, `frontend`, and
`experiments/results/behavior_model.joblib` (but no `data` directory, signing
keys, `.venv`, or build output), then run:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
python -m pytest -q --rootdir=$PWD --basetemp=(Join-Path $env:TEMP ("honeypot-pytest-" + [guid]::NewGuid().ToString("N"))) -p no:cacheprovider backend/tests
```

Verification snapshot from an isolated source copy on 2026-10-22: focused
strategy-sharing/replication tests, **13 passed, 1 warning**; complete backend
suite, **141 passed, 1 warning**. The warning is Starlette's deprecation notice
about using `httpx` with `TestClient`. Test timing varies by machine.
