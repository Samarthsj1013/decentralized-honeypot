# HTTP threat-intelligence node prototype

`app.network.replication` is an optional, standalone FastAPI application for
independently configured nodes. It does not use or migrate the main application's
ledger, signing keys, event store, or strategy-sharing database. Constructing a
`ReplicationNode` creates only the SQLite file configured for that node; merely
importing the module does not initialize storage.

## Live two-process demonstration

From the repository root, run this PowerShell command with the project virtual
environment active. It creates a unique directory under `%TEMP%`, generates
two separate encrypted test-only Ed25519 key pairs, writes independent node
configs and SQLite databases, starts two Uvicorn subprocesses on different
loopback ports, then performs publish, HTTP sync, duplicate sync, tamper reject,
Node B stop, health failure check, Node B restart, persisted-state check, and a
new post-restart sync. It prints a JSON result and leaves the demo-only keys,
configs, logs, and databases under the printed `data_directory`.

```powershell
$repoRoot = (Get-Location).Path
$python = Join-Path $repoRoot ".venv/Scripts/python.exe"
$env:PYTHONPATH = "$(Join-Path $repoRoot 'backend');$repoRoot"
$demoDataRoot = Join-Path $env:TEMP ("honeypot-live-demo-" + [guid]::NewGuid().ToString("N"))
& $python -m app.network.live_demo --data-dir $demoDataRoot
```

The demo reports `first_delivery: stored`, `signature_valid_at_node_b: true`,
`node_b_record_state: pending`, `duplicate_delivery: duplicate`, a 400 response
for tampered content, `offline_peer_status: unavailable`, then a duplicate
replay and a successful new record transfer after restart. This is verified on
localhost using separate OS processes and TCP HTTP connections. It is not a
multi-machine deployment test. The generated private keys are demonstration
keys only; never use them for real organizations.

To run that sequence without retaining generated keys or databases, omit
`--data-dir`; the runner removes only its own temporary directory when it exits.

## Security and record flow

Each node has one Ed25519 signing key, its own SQLite database, an administrator
bearer token, an explicit trusted-publisher map, and configured peer URLs. A
publisher sends a bounded, allow-listed `honeypot.threat-intel.v1` record with
an SHA-256 digest and a domain-separated Ed25519 signature. The receiving node
requires the configured peer bearer token, checks the configured publisher/key
mapping, verifies digest and signature, and persists the record as `pending`.
Private keys, actor IDs, event IDs, credentials, payloads, commands, and raw
events are not part of this schema. Indicator, classification, source family,
severity, timestamps, and aggregate observation count are included.

The importer rejects timestamps more than five minutes in the future or older
than 30 days. Pending and approved records transition to `expired` after 30
days from the signed `created_at`; expiration and decisions are kept in the
local audit table. Expired records remain in the deduplication store. Replaying
an already stored record reports its actual current state and never resets an
approval or rejection. Reusing an ID with different contents is rejected.

Peer health checks and transfers use only the configured URL. Failed checks are
reported as `unavailable`; reachable peers rejecting an exchange are reported
as `degraded`. Failed transfers return HTTP 502 and do not remove the local
outgoing record. Peer enablement, last seen/success, failure count, and sync
attempts persist in that node's separate SQLite store.
Use HTTPS and a protected secret manager for any deployment beyond loopback.
This prototype does not establish legal organization identity: node IDs are
operator-assigned labels whose keys are explicitly provisioned. It has no TLS
certificate pinning, quorum, consensus, Byzantine fault tolerance, automatic
threat enforcement, or high availability.

## Operator configuration

Generate a separate Ed25519 key pair per node and keep each private key on that
node. Distribute only public keys through an authenticated out-of-band process.
The loader accepts encrypted PKCS#8 PEM private keys when the optional
`private_key_password_env` config property names an environment variable holding
the passphrase. Protect the key file with operating-system ACLs as well. For a
local prototype, after setting `NODE_A_KEY_PASSWORD`, Python can generate one
encrypted pair (repeat with different output paths for node B). Keep the node's
database path stable across process restarts; peer state and old public
verification keys are stored there. Private keys are never stored in SQLite.

```python
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key_dir = Path(r"D:\honeypot-keys")
key_dir.mkdir(parents=True, exist_ok=True)
for name, password_env in (("org-a", "NODE_A_KEY_PASSWORD"), ("org-b", "NODE_B_KEY_PASSWORD")):
    private_key = Ed25519PrivateKey.generate()
    private_path = key_dir / f"{name}-private.pem"
    public_path = key_dir / f"{name}-public.pem"
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(os.environ[password_env].encode()),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
```

Each peer's `incoming_token_env` must name the environment variable the receiver
expects from that sender; the sender's matching `outgoing_token_env` must hold
the same random token. Use distinct random tokens per direction and keep local
admin tokens separate. The JSON configuration contains paths and environment
variable names, never bearer-token values.

Example node A configuration (`node-a.json`):

```json
{
  "node_id": "org-a-node",
  "key_id": "org-a-key-v1",
  "private_key_file": "D:/honeypot-keys/org-a-private.pem",
  "private_key_password_env": "NODE_A_KEY_PASSWORD",
  "database_path": "D:/honeypot-data/org-a-network.sqlite3",
  "admin_token_env": "NODE_A_ADMIN_TOKEN",
  "dashboard_token_env": "NODE_A_DASHBOARD_READ_TOKEN",
  "dashboard_origins": ["http://127.0.0.1:5173"],
  "trusted_publishers": {
    "org-b-node": {
      "key_id": "org-b-key-v1",
      "public_key_file": "D:/honeypot-keys/org-b-public.pem",
      "incoming_token_env": "TOKEN_B_TO_A"
    }
  },
  "peers": {
    "org-b-node": {
      "base_url": "http://127.0.0.1:8102",
      "outgoing_token_env": "TOKEN_A_TO_B"
    }
  },
  "publication_policy": {
    "enabled": false,
    "minimum_severity": "high",
    "minimum_observations": 3,
    "allowed_sources": ["suricata", "cowrie"],
    "event_type_classifications": {
      "suricata_alert": "suspicious_activity",
      "cowrie_login_failed": "brute_force"
    },
    "require_global_ip": true
  }
}
```

Node B uses its own private key and database, trusts `org-a-node` with A's
public key, and configures A's base URL. Its config has the same shape with
`node_id`/`key_id` set to `org-b-node`/`org-b-key-v1`, B's own private and
database paths, `TOKEN_A_TO_B` as A's incoming token, and `TOKEN_B_TO_A` as its
outgoing token. A trusts B with `TOKEN_B_TO_A` as B's incoming token and uses
`TOKEN_A_TO_B` as its outgoing token. For local development, use `http://` on
loopback; never send bearer tokens over an untrusted network without TLS.

Complete Node B config example:

```json
{
  "node_id": "org-b-node",
  "key_id": "org-b-key-v1",
  "private_key_file": "D:/honeypot-keys/org-b-private.pem",
  "private_key_password_env": "NODE_B_KEY_PASSWORD",
  "database_path": "D:/honeypot-data/org-b-network.sqlite3",
  "admin_token_env": "NODE_B_ADMIN_TOKEN",
  "dashboard_token_env": "NODE_B_DASHBOARD_READ_TOKEN",
  "dashboard_origins": ["http://127.0.0.1:5173"],
  "trusted_publishers": {
    "org-a-node": {
      "key_id": "org-a-key-v1",
      "public_key_file": "D:/honeypot-keys/org-a-public.pem",
      "incoming_token_env": "TOKEN_A_TO_B"
    }
  },
  "peers": {
    "org-a-node": {
      "base_url": "http://127.0.0.1:8101",
      "outgoing_token_env": "TOKEN_B_TO_A"
    }
  }
}
```
Set the referenced variables before starting each process. Values must be at
least 32 characters. For example, create random tokens in PowerShell without
printing them:

```powershell
$env:NODE_A_ADMIN_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:NODE_B_ADMIN_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:NODE_A_DASHBOARD_READ_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:NODE_B_DASHBOARD_READ_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:NODE_A_KEY_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:NODE_B_KEY_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:TOKEN_A_TO_B = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:TOKEN_B_TO_A = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

Set the same `TOKEN_A_TO_B` and `TOKEN_B_TO_A` values in both PowerShell
sessions using a secure local transfer method. Do not place token values in
either JSON config file or commit them.

Start one process per node, each with its own configuration and environment:

```powershell
$python = Join-Path (Get-Location).Path ".venv/Scripts/python.exe"
$env:HONEYPOT_NODE_CONFIG = (Resolve-Path .\node-a.json).Path
& $python -m uvicorn app.network.replication:load_node_app_from_environment --factory --app-dir backend --host 127.0.0.1 --port 8101
```

In the second PowerShell terminal, configure B's own environment values and
run:

```powershell
$python = Join-Path (Get-Location).Path ".venv/Scripts/python.exe"
$env:HONEYPOT_NODE_CONFIG = (Resolve-Path .\node-b.json).Path
& $python -m uvicorn app.network.replication:load_node_app_from_environment --factory --app-dir backend --host 127.0.0.1 --port 8102
```

Each process receives its own environment at startup. Configure these values
before each command: `DEMO_A_ADMIN_TOKEN`, `DEMO_B_ADMIN_TOKEN`,
`DEMO_A_KEY_PASSWORD`, `DEMO_B_KEY_PASSWORD`, `TOKEN_A_TO_B`, and
`TOKEN_B_TO_A`. The outgoing token in one node's config must equal the
receiving token configured for that publisher on the peer. The default project
FastAPI app does not automatically mount these optional node APIs.

## API example

Publish a local, bounded indicator observation (node admin token required):

```powershell
$now = [DateTime]::UtcNow.ToString("o")
$body = @{
  record_id = "intel-example-001"
  publisher_id = "org-a-node"
  key_id = "org-a-key-v1"
  created_at = $now
  indicator_type = "ipv4"
  indicator = "198.51.100.77"
  classification = "brute_force"
  severity = "high"
  source_system = "cowrie"
  first_seen = $now
  last_seen = $now
  observation_count = 3
} | ConvertTo-Json
$envelope = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8101/v1/intelligence/publish" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $body
```

Transfer the signed envelope to the configured B peer. The sender authenticates
the request with its configured outbound peer token. The receiving record
starts pending. An administrator can separately approve or reject it with an
audit reason; approval is a review state only and has no enforcement hook.

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8101/v1/peers/org-b-node/sync/$($envelope.record.record_id)" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" }
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8101/v1/peers/org-b-node/sync/$($envelope.record.record_id)" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" }
Invoke-RestMethod "http://127.0.0.1:8102/v1/intelligence" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" }
Invoke-RestMethod "http://127.0.0.1:8102/v1/intelligence/$($envelope.record.record_id)" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" }
Invoke-RestMethod "http://127.0.0.1:8101/v1/peers/org-b-node/health" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" }
```

The record detail response returns the signed sanitized record, its stored
state, and `signature_valid: true` only after local digest/signature
reverification. `publisher_trust_status` distinguishes a cryptographically
valid old signature from a key that is no longer trusted. An import's
`confidence_score` is `min(0.95, 0.35 + 0.10 * log2(observation_count))`; this
is a heuristic from the publisher-signed count, not a probability or claim of
truth. Same-indicator records are preserved and linked as duplicate indicators
or classification conflicts; an operator reviews the relation before deciding.

Approval and rejection are separate audited local decisions. They never trigger
blocking or enforcement:

```powershell
$decision = @{ reason = "Reviewed against local telemetry" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8102/v1/intelligence/$($envelope.record.record_id)/approve" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $decision
Invoke-RestMethod "http://127.0.0.1:8102/v1/intelligence/$($envelope.record.record_id)/audit" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" }
```

To demonstrate a tamper rejection while B is running:

```powershell
$tampered = $envelope | ConvertTo-Json -Depth 12 | ConvertFrom-Json
$tampered.record.indicator = "203.0.113.50"
try {
  Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8102/v1/intelligence/import" `
    -Headers @{ Authorization = "Bearer $env:TOKEN_A_TO_B" } `
    -ContentType "application/json" -Body ($tampered | ConvertTo-Json -Depth 12)
} catch { $_.Exception.Response.StatusCode }
```

To exercise outage/restart manually, stop only the Node B terminal with
`Ctrl+C`, then query A's peer health endpoint above (it should report
`unavailable`). Restart B with its same config/database path, repeat the sync
command (the existing record is a duplicate), then publish a new record and
sync again. Stop both foreground Uvicorn processes with `Ctrl+C` when done.

`GET /health` is a minimal peer-authenticated status probe.
`POST /v1/intelligence/import` is peer-authenticated and accepts signed JSON directly. `GET /v1/intelligence`,
`GET /v1/intelligence/{record_id}`, `POST /v1/intelligence/publish`,
`POST /v1/intelligence/observe`, and peer management calls require the local
administrator bearer token. There is no application login or user identity
system in this prototype.

## Peer registry and key lifecycle

Peer identities and URLs are configured explicitly in each node JSON file;
there is no unauthenticated discovery. `GET /v1/peers` reports enabled state,
last seen/success, failure count, and latest sanitized error. Use the
administrator-protected `POST /v1/peers/{peer_id}/disable` and `/enable` routes
to pause or resume a configured peer. Re-enabling retains its history and a
subsequent health check safely re-establishes availability.

```powershell
Invoke-RestMethod "http://127.0.0.1:8101/v1/peers" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" }
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8101/v1/peers/org-b-node/disable" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" }
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8101/v1/peers/org-b-node/enable" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" }
```

Optional publisher policy keys under each `trusted_publishers` entry are
`allowed_sources`, `allowed_classifications`, and `minimum_observations`.
Absent lists allow the schema's supported values; the default minimum is 1.
These gates supplement signature verification and do not establish indicator
truth.

Trusted keys are persisted per node. Existing configured keys are seeded as
active once. Replacement keys are never trusted merely because an envelope
names them: an operator must obtain the public key and SHA-256 fingerprint
through an authenticated out-of-band channel, stage the key, compare the
fingerprint, then explicitly activate it. The activated key may coexist with
the old key during transition. Revoke the old key only after every publisher
and receiver has been updated. Revocation rejects future imports signed by
that key and marks its already imported records `revoked`; the old signature
can still be reported as cryptographically valid, but its trust status is
revoked. Revocation is irreversible in this prototype.

Calculate the fingerprint from the raw 32-byte Ed25519 public key (not PEM
text) and stage the key on the receiver:

```powershell
$keyPath = "D:\honeypot-keys\org-a-v2-public.pem"
$fingerprint = & python -c "import hashlib,sys; from cryptography.hazmat.primitives import serialization; k=serialization.load_pem_public_key(open(sys.argv[1],'rb').read()); print(hashlib.sha256(k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest())" $keyPath
$pem = Get-Content -Raw $keyPath
$stage = @{ key_id = "org-a-key-v2"; public_key_pem = $pem; expected_fingerprint = $fingerprint } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8102/v1/publishers/org-a-node/keys" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $stage
$confirm = @{ expected_fingerprint = $fingerprint } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8102/v1/publishers/org-a-node/keys/org-a-key-v2/activate" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $confirm
# After the publisher has moved to v2 and all receivers are updated:
$oldKeyPath = "D:\honeypot-keys\org-a-public.pem"
$oldFingerprint = & python -c "import hashlib,sys; from cryptography.hazmat.primitives import serialization; k=serialization.load_pem_public_key(open(sys.argv[1],'rb').read()); print(hashlib.sha256(k.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest())" $oldKeyPath
$oldConfirm = @{ expected_fingerprint = $oldFingerprint } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8102/v1/publishers/org-a-node/keys/org-a-key-v1/revoke" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $oldConfirm
Invoke-RestMethod "http://127.0.0.1:8102/v1/publishers/audit" `
  -Headers @{ Authorization = "Bearer $env:NODE_B_ADMIN_TOKEN" }
```

For local signing-key rotation, generate a new encrypted key file, assign a new
`key_id` in that node's config, update its private-key path, and restart it
against the same node database. Its previous public key remains available for
local historical verification. Independently stage and activate the new
public key at each receiver; revoke the old key only by its confirmed
fingerprint after the cutover. Never send private keys to a peer or API.

`GET /v1/dashboard/summary` serves read-only operational data. Configure
`dashboard_token_env` and the exact dashboard origin in `dashboard_origins`.
The web UI does not call that endpoint directly: the main backend proxies it
through `GET /api/v1/network-node/dashboard` using server-only
`HONEYPOT_NODE_DASHBOARD_URL` and `HONEYPOT_NODE_DASHBOARD_TOKEN`. Do not set
either value in Vite variables. The panel shows real node peer/intelligence
state. Adaptive strategy performance is measured by the existing synthetic
`POST /api/v1/experiments/run` experiment view, not by the node registry.

## Configurable event-to-intelligence collection

`POST /v1/intelligence/observe` accepts only a small normalized projection:
source system, sensor ID, external event ID, event time/type, severity, and
source IP. The collector does not accept raw attributes, credentials, actor
IDs, or event payloads. It uses the existing telemetry event vocabulary but
does not replace the main event ledger. The standalone route is an explicit
handoff from an event forwarder. The main API can optionally forward this
projection after durable telemetry ingestion when both backend-only
`HONEYPOT_INTEL_COLLECTOR_URL` and `HONEYPOT_INTEL_COLLECTOR_TOKEN` are set.
The handoff contains no raw event attributes or actor identifier. Collector
failure is reported in the telemetry response and does not undo the persisted
event.

Collection is disabled by default. Operators must enable it and configure all
of: allowed source systems, exact event-type-to-classification mappings,
minimum severity, and a repeat-observation threshold (2 to 1000). Only source IPs
are candidates; non-global IP addresses are rejected by default to avoid
sharing private/reserved network addresses. Duplicate source/sensor/event
observations are counted once using a one-way local fingerprint. Aggregates are
grouped by normalized indicator, source family, and classification so the
signed `source_system` retains provenance. Once the threshold is met, the node
creates one signed outbound record; later observations update the local count
but do not mutate or reissue that signed record. Received records remain
`pending`. There is no blocklist, firewall, or automatic enforcement path.

Example projection (the configured mapping and threshold still apply):

```powershell
$observation = @{
  source_system = "suricata"
  sensor_id = "edge-sensor-1"
  external_event_id = "eve-event-42"
  occurred_at = [DateTime]::UtcNow.ToString("o")
  event_type = "suricata_alert"
  severity = "high"
  source_ip = "1.1.1.1"
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8101/v1/intelligence/observe" `
  -Headers @{ Authorization = "Bearer $env:NODE_A_ADMIN_TOKEN" } `
  -ContentType "application/json" -Body $observation
```

An eligible event below threshold is aggregated locally. Once the threshold is
met, the response includes the local signed record ID; an administrator still
chooses when to synchronize it to peers.

## Tests

Run `python -m pytest backend/tests/test_network_replication.py -q` for the
two-node ASGI and live-Uvicorn integration, publication criteria, trust
rejection, tampering, replay/idempotency, authentication, malformed/oversized
input, restart persistence, and peer-failure tests. Run the complete suite using the source-only temporary-copy instructions in
[`TESTING.md`](TESTING.md); tests use generated keys and temporary stores.

These are local integration tests, not an internet-scale or production
availability/security assessment. The live demonstration uses separate
Uvicorn processes and loopback TCP HTTP; other node tests use in-process ASGI
transport. Deployment operators remain responsible for transport TLS, secret
storage, firewalling, key lifecycle, monitoring, and backup policy.
